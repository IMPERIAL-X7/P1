// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {QDayVault} from "../contracts/QDayVault.sol";
import {MockPQCVerify} from "../contracts/test/Mocks.sol";

/// Shared helpers: fake-but-well-formed keys and the "oracle signature" model.
///
/// Signature model (= assumption H1): only the key holders can make the oracle accept a
/// (pk, sig, message) triple, by registering it. The attacker never registers anything; it
/// can only submit bytes it invents or bytes it saw the honest parties publish.
abstract contract Keys {
    MockPQCVerify internal constant ORACLE = MockPQCVerify(address(0x0A01));

    function _expand(bytes32 seed, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i += 32) {
            bytes32 w = keccak256(abi.encode(seed, i));
            for (uint256 j = 0; j < 32 && i + j < len; j++) out[i + j] = w[j];
        }
    }

    function _pk(bytes32 seed) internal pure returns (bytes memory) {
        return _expand(keccak256(abi.encode("pk", seed)), 2592);
    }

    /// Honest signing: produce a signature and register the triple with the oracle.
    function _sign(bytes memory pk, bytes32 secret, bytes memory m) internal returns (bytes memory sig) {
        sig = _expand(keccak256(abi.encode(secret, m)), 4627);
        ORACLE.register(keccak256(abi.encode(pk, sig, m)));
    }
}

/// Plays the honest owner, the honest guardian, anonymous executors, and the attacker.
contract Handler is Test, Keys {
    QDayVault public vault;
    bytes public pkO;
    bytes public pkG;
    bytes public pkA; // the attacker's own ML-DSA key
    bytes32 internal constant SK_O = keccak256("owner secret");
    bytes32 internal constant SK_G = keccak256("guardian secret");

    address[2] public honestTo = [address(0xB0B1), address(0xB0B2)];
    address[3] public attackers = [address(0xA771), address(0xA772), address(0xA773)];

    // Ghost variables (the test's own bookkeeping).
    uint256 public totalSigned; // sum of withdrawal amounts the owner ever signed
    uint256 public deposits;
    uint256 public attackerWins; // privileged calls the attacker made succeed
    uint256 public paidWhileFrozen;
    uint256 public calls;

    struct Rec {
        uint8 role;
        uint8 action;
        address asset;
        address to;
        uint256 amount;
        uint256 id;
        bytes32 value;
        uint64 deadline;
        bytes pk;
        bytes sig;
    }
    Rec[] internal published; // every signature the honest side ever made (the attacker sees them all)

    constructor(QDayVault v, bytes memory o, bytes memory g, bytes memory a) {
        vault = v;
        pkO = o;
        pkG = g;
        pkA = a;
    }

    function publishedCount() external view returns (uint256) {
        return published.length;
    }

    function _deadline() internal view returns (uint64) {
        return uint64(vm.getBlockTimestamp() + 600);
    }

    function _signRec(uint8 role, uint8 action, address asset, address to, uint256 amount, uint256 id, bytes32 value)
        internal
        returns (Rec memory r)
    {
        r = Rec(role, action, asset, to, amount, id, value, _deadline(), "", "");
        bytes memory m = vault.messageFor(role, r.deadline, action, asset, to, amount, id, value);
        if (role == 2) {
            r.pk = pkG;
            r.sig = _sign(pkG, SK_G, m);
        } else {
            r.pk = pkO;
            r.sig = _sign(pkO, SK_O, m);
        }
        published.push(r);
    }

    // ───────────────────────────────────────── honest owner / guardian

    function honestWithdraw(uint256 amount, uint256 toSeed) external {
        calls++;
        amount = bound(amount, 1, 5 ether);
        address to = honestTo[toSeed % 2];
        Rec memory r = _signRec(1, 1, address(0), to, amount, 0, 0);
        totalSigned += amount; // authorised the moment it is signed
        bool wasFrozen = vault.frozen();
        try vault.withdraw(address(0), to, amount, r.deadline, r.pk, r.sig) returns (uint256 id) {
            if (wasFrozen && id == 0) paidWhileFrozen++;
        } catch {}
    }

    function honestProposeLimit(uint256 limit) external {
        calls++;
        limit = bound(limit, 0, 3 ether);
        Rec memory r = _signRec(1, 4, address(0), address(0), limit, 0, 0);
        try vault.proposeLimit(address(0), limit, r.deadline, r.pk, r.sig) {} catch {}
    }

    function honestProposeDelay(uint256 d) external {
        calls++;
        d = bound(d, 5 minutes, 2 days);
        Rec memory r = _signRec(1, 5, address(0), address(0), d, 0, 0);
        try vault.proposeDelay(uint64(d), r.deadline, r.pk, r.sig) {} catch {}
    }

    function honestCancel(uint256 idSeed, bool byGuardian) external {
        calls++;
        uint256 n = vault.itemCount();
        if (n == 0) return;
        uint256 id = 1 + (idSeed % n);
        uint8 role = byGuardian ? 2 : 1;
        Rec memory r = _signRec(role, 6, address(0), address(0), 0, id, 0);
        try vault.cancel(id, role, r.deadline, r.pk, r.sig) {} catch {}
    }

    function honestFreeze(bool byGuardian) external {
        calls++;
        uint8 role = byGuardian ? 2 : 1;
        Rec memory r = _signRec(role, 7, address(0), address(0), 0, 0, 0);
        try vault.freeze(role, r.deadline, r.pk, r.sig) {} catch {}
    }

    function honestUnfreeze() external {
        calls++;
        uint64 dl = _deadline();
        bytes memory m = vault.messageFor(3, dl, 8, address(0), address(0), 0, 0, 0);
        bytes memory so = _sign(pkO, SK_O, m);
        bytes memory sg = _sign(pkG, SK_G, m);
        try vault.unfreeze(dl, pkO, so, pkG, sg) {} catch {}
    }

    function deposit(uint256 amount) external {
        calls++;
        amount = bound(amount, 0, 10 ether);
        vm.deal(address(this), amount);
        (bool ok,) = address(vault).call{value: amount}("");
        require(ok);
        deposits += amount;
    }

    /// Anyone (honest or attacker) may execute a matured item: it does only what was signed.
    function anyoneExecute(uint256 idSeed, uint256 who) external {
        calls++;
        uint256 n = vault.itemCount();
        if (n == 0) return;
        uint256 id = 1 + (idSeed % n);
        bool wasFrozen = vault.frozen();
        QDayVault.Item memory it = vault.getItem(id);
        vm.prank(attackers[who % 3]);
        try vault.execute(id) {
            if (wasFrozen && it.kind == 1) paidWhileFrozen++;
        } catch {}
    }

    function warp(uint256 secs) external {
        calls++;
        vm.warp(vm.getBlockTimestamp() + bound(secs, 0, 2 days));
    }

    // ───────────────────────────────────────── attacker

    /// Withdraw to itself with invented bytes and any of the known public keys.
    function attackWithdraw(uint256 amount, uint256 who, uint256 pkChoice, bytes32 sigSeed) external {
        calls++;
        address to = attackers[who % 3];
        bytes memory pk = pkChoice % 3 == 0 ? pkO : (pkChoice % 3 == 1 ? pkA : pkG);
        bytes memory sig = _expand(sigSeed, 4627);
        vm.prank(to);
        try vault.withdraw(address(0), to, bound(amount, 1, 50 ether), _deadline(), pk, sig) {
            attackerWins++;
        } catch {}
    }

    /// The attacker signs correctly-built messages with ITS OWN ML-DSA key (registered with the
    /// oracle, so these signatures are genuinely valid under pkA) and tries every entry point.
    function attackOwnKey(uint256 which, uint256 who) external {
        calls++;
        address me = attackers[who % 3];
        uint64 dl = _deadline();
        uint8 role = which % 2 == 0 ? 1 : 2;
        bytes32 sk = keccak256("attacker secret");
        vm.startPrank(me);
        uint256 w = which % 6;
        if (w == 0) {
            bytes memory s = _sign(pkA, sk, vault.messageFor(1, dl, 1, address(0), me, 1 ether, 0, 0));
            try vault.withdraw(address(0), me, 1 ether, dl, pkA, s) { attackerWins++; } catch {}
        } else if (w == 1) {
            bytes memory s = _sign(pkA, sk, vault.messageFor(role, dl, 7, address(0), address(0), 0, 0, 0));
            try vault.freeze(role, dl, pkA, s) { attackerWins++; } catch {}
        } else if (w == 2) {
            bytes32 h = keccak256(pkA);
            bytes memory s = _sign(pkA, sk, vault.messageFor(role, dl, 2, address(0), address(0), 0, 0, h));
            try vault.proposeOwnerKey(pkA, role, dl, pkA, s) { attackerWins++; } catch {}
        } else if (w == 3) {
            bytes memory s = _sign(pkA, sk, vault.messageFor(1, dl, 4, address(0), address(0), 100 ether, 0, 0));
            try vault.proposeLimit(address(0), 100 ether, dl, pkA, s) { attackerWins++; } catch {}
        } else if (w == 4) {
            bytes memory m = vault.messageFor(3, dl, 8, address(0), address(0), 0, 0, 0);
            bytes memory s = _sign(pkA, sk, m);
            try vault.unfreeze(dl, pkA, s, pkA, s) { attackerWins++; } catch {}
            try vault.unfreeze(dl, pkO, s, pkG, s) { attackerWins++; } catch {}
        } else {
            bytes32 h = keccak256(pkA);
            bytes memory s = _sign(pkA, sk, vault.messageFor(1, dl, 3, address(0), address(0), 0, 0, h));
            try vault.proposeGuardianKey(pkA, dl, pkA, s) { attackerWins++; } catch {}
        }
        vm.stopPrank();
    }

    /// Replay any signature the honest side ever published, unchanged or tampered with,
    /// into the function it was made for or into a different one.
    function attackReplay(uint256 idx, uint256 mutation, uint256 who) external {
        calls++;
        if (published.length == 0) return;
        Rec memory r = published[idx % published.length];
        address me = attackers[who % 3];
        uint256 mu = mutation % 8;
        bool tampered = _uses(r.action, mu);
        if (mu == 1) r.to = me;
        else if (mu == 2) r.amount += 1;
        else if (mu == 3) r.deadline += 1;
        else if (mu == 4) r.role = r.role == 1 ? 2 : 1;
        else if (mu == 5) r.asset = address(vault);
        else if (mu == 6) r.id += 1;
        else if (mu == 7) r.action = uint8(1 + (uint256(r.action) % 7)); // a different action
        bool wasFrozen = vault.frozen();
        bool ok = _dispatch(r, me);
        if (ok && tampered) attackerWins++;
        if (ok && wasFrozen && r.action == 1) paidWhileFrozen++;
        // An untampered replay that succeeds is only possible for a signature the honest
        // side made but whose own submission failed; it does exactly what was signed.
    }

    /// Whether mutation `mu` changes an argument that the function for `action` actually uses
    /// (1 to, 2 amount, 3 deadline, 4 role, 5 asset, 6 id, 7 action).
    function _uses(uint8 action, uint256 mu) internal pure returns (bool) {
        if (mu == 0) return false;
        if (mu == 3 || mu == 7) return true;
        if (action == 1) return mu == 1 || mu == 2 || mu == 5;
        if (action == 2) return true; // new key is always the attacker's
        if (action == 3) return true;
        if (action == 4) return mu == 2 || mu == 5;
        if (action == 5) return mu == 2;
        if (action == 6) return mu == 4 || mu == 6;
        return mu == 4; // freeze
    }

    function _dispatch(Rec memory r, address me) internal returns (bool ok) {
        vm.startPrank(me);
        if (r.action == 1) {
            try vault.withdraw(r.asset, r.to, r.amount, r.deadline, r.pk, r.sig) { ok = true; } catch {}
        } else if (r.action == 2) {
            try vault.proposeOwnerKey(pkA, r.role, r.deadline, r.pk, r.sig) { ok = true; } catch {}
        } else if (r.action == 3) {
            try vault.proposeGuardianKey(pkA, r.deadline, r.pk, r.sig) { ok = true; } catch {}
        } else if (r.action == 4) {
            try vault.proposeLimit(r.asset, r.amount, r.deadline, r.pk, r.sig) { ok = true; } catch {}
        } else if (r.action == 5) {
            try vault.proposeDelay(uint64(r.amount), r.deadline, r.pk, r.sig) { ok = true; } catch {}
        } else if (r.action == 6) {
            try vault.cancel(r.id, r.role, r.deadline, r.pk, r.sig) { ok = true; } catch {}
        } else {
            try vault.freeze(r.role, r.deadline, r.pk, r.sig) { ok = true; } catch {}
        }
        vm.stopPrank();
    }
}

contract QDayVaultInvariantTest is Test, Keys {
    QDayVault internal vault;
    Handler internal handler;
    bytes internal pkO;
    bytes internal pkG;
    uint256 internal constant FUNDS = 100 ether;

    function setUp() public {
        vm.etch(address(0x0A01), type(MockPQCVerify).runtimeCode);
        pkO = _pk("owner");
        pkG = _pk("guardian");
        vault = new QDayVault(pkO, pkG, address(0), 1 ether, 1 hours);
        vm.deal(address(vault), FUNDS);
        handler = new Handler(vault, pkO, pkG, _pk("attacker"));
        targetContract(address(handler));
    }

    /// Guard against a vacuous campaign: drive the handler by hand and check that honest
    /// paths really move money, queue, freeze and unfreeze, and that attacks really run.
    function test_handlerIsNotVacuous() public {
        handler.honestWithdraw(0.5 ether, 0); // instant
        assertEq(handler.honestTo(0).balance, 0.5 ether);
        handler.honestWithdraw(4 ether, 1); // queued
        assertEq(vault.itemCount(), 1);
        handler.warp(2 hours);
        handler.anyoneExecute(0, 0);
        assertEq(handler.honestTo(1).balance, 4 ether);
        handler.honestFreeze(true);
        assertTrue(vault.frozen());
        handler.honestUnfreeze();
        assertFalse(vault.frozen());
        for (uint256 i = 0; i < handler.publishedCount(); i++) {
            for (uint256 mu = 0; mu < 8; mu++) handler.attackReplay(i, mu, mu);
        }
        for (uint256 w = 0; w < 12; w++) handler.attackOwnKey(w, w);
        handler.attackWithdraw(1 ether, 0, 0, keccak256("x"));
        assertEq(handler.attackerWins(), 0);
        assertEq(handler.attackers(0).balance + handler.attackers(1).balance + handler.attackers(2).balance, 0);
    }

    /// T1/T2: the attacker never makes a privileged call succeed, with invented, own-key,
    /// replayed or tampered signatures.
    function invariant_attackerNeverWins() public view {
        assertEq(handler.attackerWins(), 0);
    }

    /// T1: attacker addresses never receive a single wei.
    function invariant_attackersNeverPaid() public view {
        for (uint256 i = 0; i < 3; i++) assertEq(handler.attackers(i).balance, 0);
    }

    /// T1: everything that left the vault went to honest recipients and was signed by the owner.
    function invariant_outflowSignedAndHonest() public view {
        uint256 out = FUNDS + handler.deposits() - address(vault).balance;
        assertEq(out, handler.honestTo(0).balance + handler.honestTo(1).balance);
        assertLe(out, handler.totalSigned());
    }

    /// T4/T5: nothing is paid while frozen.
    function invariant_noPaymentWhileFrozen() public view {
        assertEq(handler.paidWhileFrozen(), 0);
    }

    /// Keys never change (the honest side never proposes a key change in this campaign).
    function invariant_keysUnchanged() public view {
        assertEq(vault.ownerKeyHash(), keccak256(pkO));
        assertEq(vault.guardianKeyHash(), keccak256(pkG));
    }

    /// Settings stay inside their bounds.
    function invariant_settingsInBounds() public view {
        assertGe(vault.delay(), vault.MIN_DELAY());
        assertLe(vault.delay(), vault.MAX_DELAY());
        assertLe(vault.dailyLimit(address(0)), 3 ether);
    }
}

/// Stateless fuzz tests of single properties.
contract QDayVaultFuzzTest is Test, Keys {
    QDayVault internal vault;
    bytes internal pkO;
    bytes internal pkG;
    bytes32 internal constant SK_O = keccak256("owner secret");

    function setUp() public {
        vm.etch(address(0x0A01), type(MockPQCVerify).runtimeCode);
        pkO = _pk("owner");
        pkG = _pk("guardian");
        vault = new QDayVault(pkO, pkG, address(0), 1 ether, 1 hours);
        vm.deal(address(vault), 100 ether);
    }

    /// Any invented signature, any recipient, any amount, any sender: refused.
    function testFuzz_inventedSignatureNeverWorks(bytes calldata sig, address to, uint256 amount, address sender) public {
        vm.assume(to != address(0) && amount != 0);
        vm.prank(sender);
        vm.expectRevert();
        vault.withdraw(address(0), to, amount, uint64(block.timestamp + 60), pkO, sig);
    }

    /// Lemma 3 shape: every message is 384 bytes and starts with 0xFF.
    function testFuzz_messageShape(uint8 role, uint64 dl, uint8 action, address a, address to, uint256 amt, uint256 id, bytes32 v)
        public
        view
    {
        bytes memory m = vault.messageFor(role, dl, action, a, to, amt, id, v);
        assertEq(m.length, 384);
        assertEq(uint8(m[0]), 0xFF);
    }

    /// Lemma 1: different fields => different messages.
    function testFuzz_messageInjective(uint8 action1, uint8 action2, address to1, address to2, uint256 amt1, uint256 amt2) public view {
        vm.assume(action1 != action2 || to1 != to2 || amt1 != amt2);
        bytes memory m1 = vault.messageFor(1, 1, action1, address(0), to1, amt1, 0, 0);
        bytes memory m2 = vault.messageFor(1, 1, action2, address(0), to2, amt2, 0, 0);
        assertTrue(keccak256(m1) != keccak256(m2));
    }

    /// Theorem 4(a): within one UTC day, instant withdrawals never exceed the daily limit.
    function testFuzz_instantWithinLimit(uint256[8] memory amounts) public {
        // Track time explicitly: under via-IR, block.timestamp can be cached across vm.warp.
        uint256 t = (1_800_000_000 / 1 days) * 1 days + 1; // just after a UTC midnight
        vm.warp(t);
        uint256 instant;
        address to = address(0xB0B);
        for (uint256 i = 0; i < amounts.length; i++) {
            uint256 amt = bound(amounts[i], 1, 2 ether);
            uint64 dl = uint64(t + 60);
            bytes memory m = vault.messageFor(1, dl, 1, address(0), to, amt, 0, 0);
            bytes memory sig = _sign(pkO, SK_O, m);
            uint256 before = to.balance;
            vault.withdraw(address(0), to, amt, dl, pkO, sig);
            instant += to.balance - before;
            t += 600; // 8 * 600 s stays inside the same UTC day
            vm.warp(t);
        }
        assertLe(instant, 1 ether);
    }

    /// Theorem 4(c): a queued withdrawal never executes before its eta, whatever the timing.
    function testFuzz_delayEnforced(uint256 amount, uint256 wait) public {
        amount = bound(amount, 1 ether + 1, 50 ether); // above the limit => queued
        wait = bound(wait, 0, 1 hours - 1);
        uint256 t = vm.getBlockTimestamp();
        uint64 dl = uint64(t + 60);
        address to = address(0xB0B);
        bytes memory sig = _sign(pkO, SK_O, vault.messageFor(1, dl, 1, address(0), to, amount, 0, 0));
        uint256 id = vault.withdraw(address(0), to, amount, dl, pkO, sig);
        assertGt(id, 0);
        vm.warp(t + wait);
        vm.expectRevert(QDayVault.TooEarly.selector);
        vault.execute(id);
        vm.warp(t + 1 hours);
        vault.execute(id);
        assertEq(to.balance, amount);
    }

    /// Lemma 7: wrong-length keys or signatures never reach the precompile.
    function testFuzz_lengthsChecked(bytes calldata pk, bytes calldata sig) public {
        vm.assume(pk.length != 2592 || sig.length != 4627);
        vm.expectRevert();
        vault.freeze(1, uint64(block.timestamp + 60), pk, sig);
    }
}
