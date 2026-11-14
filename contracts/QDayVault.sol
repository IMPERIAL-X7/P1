// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @title Q-Day Vault
/// @notice A vault whose funds and settings change only with ML-DSA-87 (post-quantum)
///         signatures, verified on chain by QoreChain's `pqcVerify` precompile.
///         `msg.sender` is never used for authorisation, so a stolen ECDSA key, or one
///         broken by a quantum computer, cannot move anything.
/// @dev    The security argument for every function is in docs/SECURITY_PROOFS.md.
///         Section numbers in comments (e.g. "§4.2") refer to that document.
contract QDayVault {
    // ─────────────────────────────────────────────────────────────── constants

    /// First 32 bytes of every signed message: 0xFF ‖ "QDAY-VAULT-v1" ‖ zero padding.
    /// The 0xFF byte keeps vault messages apart from every QoreChain sign-bytes format (§4.3).
    bytes32 public constant DOMAIN_TAG = 0xff514441592d5641554c542d7631000000000000000000000000000000000000;

    address public constant PQC_VERIFY = address(0x0A01);
    address public constant PQC_KEY_STATUS = address(0x0A02);
    uint8 public constant ALG_ML_DSA_87 = 1;
    uint256 public constant PK_LEN = 2592; // ML-DSA-87 public key
    uint256 public constant SIG_LEN = 4627; // ML-DSA-87 signature

    uint64 public constant MIN_DELAY = 5 minutes;
    uint64 public constant MAX_DELAY = 30 days;

    address public constant NATIVE = address(0); // "asset" value for native QOR

    // Signer roles. Each role has its own nonce.
    uint8 public constant ROLE_OWNER = 1;
    uint8 public constant ROLE_GUARDIAN = 2;
    uint8 public constant ROLE_JOINT = 3; // owner and guardian sign the same message

    // Actions. Values 1..5 are also the kinds of queued items.
    uint8 public constant ACT_WITHDRAW = 1;
    uint8 public constant ACT_SET_OWNER_KEY = 2;
    uint8 public constant ACT_SET_GUARDIAN_KEY = 3;
    uint8 public constant ACT_SET_LIMIT = 4;
    uint8 public constant ACT_SET_DELAY = 5;
    uint8 public constant ACT_CANCEL = 6;
    uint8 public constant ACT_FREEZE = 7;
    uint8 public constant ACT_UNFREEZE = 8;

    uint8 public constant STATUS_QUEUED = 1;
    uint8 public constant STATUS_EXECUTED = 2;
    uint8 public constant STATUS_CANCELLED = 3;

    // ─────────────────────────────────────────────────────────────── state

    /// keccak256 of the owner's ML-DSA-87 public key. Never zero.
    bytes32 public ownerKeyHash;
    /// keccak256 of the guardian's ML-DSA-87 public key, or zero for "no guardian".
    bytes32 public guardianKeyHash;
    /// Seconds a queued item waits before it can execute.
    uint64 public delay;
    /// While true, no withdrawal can happen (instant or queued).
    bool public frozen;

    /// Next unused nonce for each role.
    mapping(uint8 role => uint256) public nonces;
    /// Increases every time that role's key is replaced. Never decreases.
    mapping(uint8 role => uint256) public keyVersion;
    /// Per-asset amount that may leave instantly per UTC day. 0 = every withdrawal is queued.
    mapping(address asset => uint256) public dailyLimit;

    struct Spend {
        uint256 day; // block.timestamp / 1 days
        uint256 amount; // instant withdrawals on that day
    }
    mapping(address asset => Spend) public spent;

    struct Item {
        uint8 kind; // ACT_WITHDRAW .. ACT_SET_DELAY
        uint8 status; // STATUS_*
        uint8 signerRole; // role whose key authorised this item
        uint64 eta; // earliest execution time
        address asset;
        address to;
        uint256 amount; // withdraw amount, new limit, or new delay
        bytes32 value; // new key hash for key changes
        uint256 signerVersion; // keyVersion of the signer's role when queued; dies once that key is replaced
    }
    Item[] internal _items;

    uint256 private _lock = 1;

    // ─────────────────────────────────────────────────────────────── events

    event Deposited(address indexed from, uint256 amount);
    event Authorized(uint8 indexed role, uint256 nonce, uint8 indexed action);
    event Withdrawn(uint256 indexed id, address indexed asset, address indexed to, uint256 amount); // id 0 = instant
    event Queued(uint256 indexed id, uint8 indexed kind, address asset, address to, uint256 amount, bytes32 value, uint64 eta);
    event Executed(uint256 indexed id, uint8 indexed kind);
    event Cancelled(uint256 indexed id, uint8 indexed role);
    event Frozen(uint8 indexed role);
    event Unfrozen();

    // ─────────────────────────────────────────────────────────────── errors

    error Reentrancy();
    error BadKey();
    error SameKeys();
    error KeyNotBound();
    error BadDelay();
    error BadRole();
    error Expired();
    error WrongKey();
    error BadSignature();
    error IsFrozen();
    error NotFrozen();
    error BadWithdrawal();
    error NotQueued();
    error TooEarly();
    error StaleKey();
    error TransferFailed();

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    // ─────────────────────────────────────────────────────────────── setup

    /// @param ownerPk       owner's ML-DSA-87 public key (2,592 bytes)
    /// @param guardianPk    guardian's ML-DSA-87 public key, or empty for no guardian
    /// @param ownerAccount  if non-zero, `ownerPk` must be this account's on-chain registered
    ///                      ML-DSA-87 key with proof of possession (checked via pqcKeyStatus)
    /// @param nativeLimit   native QOR (wei) that may leave instantly per UTC day
    /// @param delay_        queue delay in seconds, MIN_DELAY..MAX_DELAY
    constructor(bytes memory ownerPk, bytes memory guardianPk, address ownerAccount, uint256 nativeLimit, uint64 delay_) {
        if (!_wellFormedKey(ownerPk)) revert BadKey();
        ownerKeyHash = keccak256(ownerPk);
        if (guardianPk.length != 0) {
            if (!_wellFormedKey(guardianPk)) revert BadKey();
            guardianKeyHash = keccak256(guardianPk);
            if (guardianKeyHash == ownerKeyHash) revert SameKeys();
        }
        if (ownerAccount != address(0)) {
            (bool ok, bytes memory ret) =
                PQC_KEY_STATUS.staticcall(abi.encodeWithSignature("pqcKeyStatus(address)", ownerAccount));
            // An inactive precompile returns success with empty data: refuse it (fail closed).
            if (!ok || ret.length == 0) revert KeyNotBound();
            (bool registered, uint8 alg, bytes memory pk, bool possessionProven) =
                abi.decode(ret, (bool, uint8, bytes, bool));
            if (!registered || alg != ALG_ML_DSA_87 || !possessionProven || keccak256(pk) != ownerKeyHash) {
                revert KeyNotBound();
            }
        }
        if (delay_ < MIN_DELAY || delay_ > MAX_DELAY) revert BadDelay();
        delay = delay_;
        dailyLimit[NATIVE] = nativeLimit;
        // Item 0 is a placeholder so that id 0 can mean "instant" in events.
        _items.push();
    }

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    // ─────────────────────────────────────────────────────────────── owner actions

    /// @notice Withdraw `amount` of `asset` to `to`. Signed by the owner key.
    ///         Executes now if it fits in today's limit, otherwise is queued for `delay`.
    /// @return id 0 if executed now, otherwise the id of the queued item
    function withdraw(address asset, address to, uint256 amount, uint64 deadline, bytes calldata pk, bytes calldata sig)
        external
        nonReentrant
        returns (uint256 id)
    {
        if (frozen) revert IsFrozen();
        if (amount == 0 || to == address(0) || (asset != NATIVE && asset.code.length == 0)) revert BadWithdrawal();
        _authorize(ROLE_OWNER, deadline, ACT_WITHDRAW, asset, to, amount, 0, bytes32(0), pk, sig);

        uint256 today = block.timestamp / 1 days;
        Spend storage s = spent[asset];
        uint256 used = s.day == today ? s.amount : 0;
        if (used + amount <= dailyLimit[asset]) {
            s.day = today;
            s.amount = used + amount;
            _transfer(asset, to, amount);
            emit Withdrawn(0, asset, to, amount);
            return 0;
        }
        return _queue(ROLE_OWNER, ACT_WITHDRAW, asset, to, amount, bytes32(0));
    }

    /// @notice Queue a change of the guardian key (empty `newGuardianPk` removes the guardian).
    function proposeGuardianKey(bytes calldata newGuardianPk, uint64 deadline, bytes calldata pk, bytes calldata sig)
        external
        nonReentrant
        returns (uint256)
    {
        bytes32 h = bytes32(0); // zero = "remove the guardian"
        if (newGuardianPk.length != 0) {
            if (!_wellFormedKey(newGuardianPk)) revert BadKey();
            h = keccak256(newGuardianPk);
        }
        _authorize(ROLE_OWNER, deadline, ACT_SET_GUARDIAN_KEY, NATIVE, address(0), 0, 0, h, pk, sig);
        return _queue(ROLE_OWNER, ACT_SET_GUARDIAN_KEY, NATIVE, address(0), 0, h);
    }

    /// @notice Queue a new instant-withdrawal limit for `asset`.
    function proposeLimit(address asset, uint256 newLimit, uint64 deadline, bytes calldata pk, bytes calldata sig)
        external
        nonReentrant
        returns (uint256)
    {
        _authorize(ROLE_OWNER, deadline, ACT_SET_LIMIT, asset, address(0), newLimit, 0, bytes32(0), pk, sig);
        return _queue(ROLE_OWNER, ACT_SET_LIMIT, asset, address(0), newLimit, bytes32(0));
    }

    /// @notice Queue a new queue delay.
    function proposeDelay(uint64 newDelay, uint64 deadline, bytes calldata pk, bytes calldata sig)
        external
        nonReentrant
        returns (uint256)
    {
        if (newDelay < MIN_DELAY || newDelay > MAX_DELAY) revert BadDelay();
        _authorize(ROLE_OWNER, deadline, ACT_SET_DELAY, NATIVE, address(0), newDelay, 0, bytes32(0), pk, sig);
        return _queue(ROLE_OWNER, ACT_SET_DELAY, NATIVE, address(0), newDelay, bytes32(0));
    }

    // ─────────────────────────────────────────────────────────────── owner-or-guardian actions

    /// @notice Queue a new owner key. The owner uses this to rotate; the guardian uses it to
    ///         recover a lost owner key. Either way it waits `delay` and can be cancelled.
    function proposeOwnerKey(bytes calldata newOwnerPk, uint8 role, uint64 deadline, bytes calldata pk, bytes calldata sig)
        external
        nonReentrant
        returns (uint256)
    {
        if (!_wellFormedKey(newOwnerPk)) revert BadKey();
        bytes32 h = keccak256(newOwnerPk);
        _authorize(_singleRole(role), deadline, ACT_SET_OWNER_KEY, NATIVE, address(0), 0, 0, h, pk, sig);
        return _queue(role, ACT_SET_OWNER_KEY, NATIVE, address(0), 0, h);
    }

    /// @notice Cancel a queued item. Owner or guardian.
    function cancel(uint256 id, uint8 role, uint64 deadline, bytes calldata pk, bytes calldata sig) external nonReentrant {
        if (id == 0 || id >= _items.length || _items[id].status != STATUS_QUEUED) revert NotQueued();
        _authorize(_singleRole(role), deadline, ACT_CANCEL, NATIVE, address(0), 0, id, bytes32(0), pk, sig);
        _items[id].status = STATUS_CANCELLED;
        emit Cancelled(id, role);
    }

    /// @notice Stop all withdrawals. Owner or guardian.
    function freeze(uint8 role, uint64 deadline, bytes calldata pk, bytes calldata sig) external nonReentrant {
        _authorize(_singleRole(role), deadline, ACT_FREEZE, NATIVE, address(0), 0, 0, bytes32(0), pk, sig);
        frozen = true;
        emit Frozen(role);
    }

    /// @notice Lift a freeze. Needs the owner AND (if one is set) the guardian to sign the same message.
    function unfreeze(
        uint64 deadline,
        bytes calldata ownerPk,
        bytes calldata ownerSig,
        bytes calldata guardianPk,
        bytes calldata guardianSig
    ) external nonReentrant {
        if (!frozen) revert NotFrozen();
        if (block.timestamp > deadline) revert Expired();
        uint256 nonce = nonces[ROLE_JOINT];
        bytes memory m = _message(ROLE_JOINT, nonce, deadline, ACT_UNFREEZE, NATIVE, address(0), 0, 0, bytes32(0));
        _check(ownerKeyHash, ownerPk, ownerSig, m);
        if (guardianKeyHash != bytes32(0)) _check(guardianKeyHash, guardianPk, guardianSig, m);
        nonces[ROLE_JOINT] = nonce + 1;
        emit Authorized(ROLE_JOINT, nonce, ACT_UNFREEZE);
        frozen = false;
        emit Unfrozen();
    }

    // ─────────────────────────────────────────────────────────────── anyone

    /// @notice Execute a queued item whose delay has passed. Needs no signature: the item was
    ///         authorised when it was queued.
    function execute(uint256 id) external nonReentrant {
        if (id == 0 || id >= _items.length) revert NotQueued();
        Item storage it = _items[id];
        if (it.status != STATUS_QUEUED) revert NotQueued();
        if (block.timestamp < it.eta) revert TooEarly();
        // The key that authorised the item must still be that role's key (Lemma 6).
        if (keyVersion[it.signerRole] != it.signerVersion) revert StaleKey();
        it.status = STATUS_EXECUTED;
        uint8 kind = it.kind;

        if (kind == ACT_WITHDRAW) {
            if (frozen) revert IsFrozen();
            _transfer(it.asset, it.to, it.amount);
            emit Withdrawn(id, it.asset, it.to, it.amount);
        } else if (kind == ACT_SET_OWNER_KEY) {
            if (it.value == guardianKeyHash) revert SameKeys();
            ownerKeyHash = it.value;
            keyVersion[ROLE_OWNER] += 1; // every other owner-signed item is now dead (Lemma 6)
        } else if (kind == ACT_SET_GUARDIAN_KEY) {
            if (it.value == ownerKeyHash) revert SameKeys();
            guardianKeyHash = it.value;
            keyVersion[ROLE_GUARDIAN] += 1; // every other guardian-signed item is now dead (Lemma 6)
        } else if (kind == ACT_SET_LIMIT) {
            dailyLimit[it.asset] = it.amount;
        } else {
            delay = uint64(it.amount);
        }
        emit Executed(id, kind);
    }

    // ─────────────────────────────────────────────────────────────── views

    /// @notice The exact bytes a signer must sign for the next action of `role`.
    ///         (A careful client rebuilds these bytes itself instead of trusting an RPC.)
    function messageFor(
        uint8 role,
        uint64 deadline,
        uint8 action,
        address asset,
        address to,
        uint256 amount,
        uint256 id,
        bytes32 value
    ) external view returns (bytes memory) {
        return _message(role, nonces[role], deadline, action, asset, to, amount, id, value);
    }

    function itemCount() external view returns (uint256) {
        return _items.length - 1;
    }

    function getItem(uint256 id) external view returns (Item memory) {
        return _items[id];
    }

    /// @notice How much of `asset` can still leave instantly today.
    function remainingToday(address asset) external view returns (uint256) {
        Spend memory s = spent[asset];
        uint256 used = s.day == block.timestamp / 1 days ? s.amount : 0;
        uint256 lim = dailyLimit[asset];
        return used >= lim ? 0 : lim - used;
    }

    // ─────────────────────────────────────────────────────────────── internals

    /// Build the signed message: 12 static ABI words, always exactly 384 bytes (§4.1).
    function _message(
        uint8 role,
        uint256 nonce,
        uint64 deadline,
        uint8 action,
        address asset,
        address to,
        uint256 amount,
        uint256 id,
        bytes32 value
    ) internal view returns (bytes memory) {
        return abi.encode(DOMAIN_TAG, block.chainid, address(this), role, nonce, deadline, action, asset, to, amount, id, value);
    }

    /// Check one signature by `role` over the action, then consume that role's nonce.
    function _authorize(
        uint8 role,
        uint64 deadline,
        uint8 action,
        address asset,
        address to,
        uint256 amount,
        uint256 id,
        bytes32 value,
        bytes calldata pk,
        bytes calldata sig
    ) internal {
        if (block.timestamp > deadline) revert Expired();
        bytes32 keyHash = _keyOf(role);
        uint256 nonce = nonces[role];
        _check(keyHash, pk, sig, _message(role, nonce, deadline, action, asset, to, amount, id, value));
        nonces[role] = nonce + 1;
        emit Authorized(role, nonce, action);
    }

    /// Revert unless `sig` is a valid ML-DSA-87 signature on `m` under the key whose hash is `keyHash`.
    function _check(bytes32 keyHash, bytes calldata pk, bytes calldata sig, bytes memory m) internal view {
        if (keyHash == bytes32(0) || pk.length != PK_LEN || keccak256(pk) != keyHash) revert WrongKey();
        if (sig.length != SIG_LEN) revert BadSignature();
        (bool ok, bytes memory ret) =
            PQC_VERIFY.staticcall(abi.encodeWithSignature("pqcVerify(bytes,bytes,bytes)", pk, sig, m));
        // Empty return data (inactive precompile) or anything but an ABI `true` fails closed.
        if (!ok || ret.length != 32 || abi.decode(ret, (uint256)) != 1) revert BadSignature();
    }

    function _keyOf(uint8 role) internal view returns (bytes32) {
        return role == ROLE_OWNER ? ownerKeyHash : guardianKeyHash;
    }

    function _singleRole(uint8 role) internal pure returns (uint8) {
        if (role != ROLE_OWNER && role != ROLE_GUARDIAN) revert BadRole();
        return role;
    }

    function _queue(uint8 role, uint8 kind, address asset, address to, uint256 amount, bytes32 value)
        internal
        returns (uint256 id)
    {
        id = _items.length;
        uint64 eta = uint64(block.timestamp) + delay;
        _items.push(Item(kind, STATUS_QUEUED, role, eta, asset, to, amount, value, keyVersion[role]));
        emit Queued(id, kind, asset, to, amount, value, eta);
    }

    function _transfer(address asset, address to, uint256 amount) internal {
        bool ok;
        if (asset == NATIVE) {
            (ok,) = to.call{value: amount}("");
        } else {
            bytes memory ret;
            (ok, ret) = asset.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
            ok = ok && (ret.length == 0 || (ret.length == 32 && abi.decode(ret, (uint256)) == 1));
        }
        if (!ok) revert TransferFailed();
    }

    /// A usable ML-DSA-87 public key: the right length, and not "degenerate" (t1 all zero,
    /// for which anyone can forge signatures; see the QoreChain SDK's isDegeneratePqcPublicKey).
    function _wellFormedKey(bytes memory pk) internal pure returns (bool) {
        if (pk.length != PK_LEN) return false;
        for (uint256 i = 32; i < PK_LEN; i++) {
            if (pk[i] != 0) return true;
        }
        return false;
    }
}
