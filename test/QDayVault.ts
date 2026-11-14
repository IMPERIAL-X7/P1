/**
 * Unit tests for QDayVault on Hardhat's simulated chain.
 *
 * The QoreChain precompiles do not exist locally, so test doubles are installed at their
 * addresses (contracts/test/Mocks.sol). Signatures are REAL ML-DSA-87 signatures from the
 * QoreChain SDK, checked off chain with the real algorithm before the oracle mock is told
 * about them. Each `describe` block names the claim of docs/SECURITY_PROOFS.md it tests.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { encodeAbiParameters, keccak256, parseEther, type Address, type Hex } from "viem";
import { generatePqcKeypair } from "@qorechain/sdk";

import { Action, buildMessage, NATIVE, Role, signMessage, toHexBytes, ZERO32, type PqcKey } from "../scripts/lib/vault.js";

const PQC_VERIFY: Address = "0x0000000000000000000000000000000000000a01";
const PQC_STATUS: Address = "0x0000000000000000000000000000000000000a02";
const DAY = 86_400n;
const DELAY = 3_600n; // 1 hour
const LIMIT = parseEther("1"); // 1 QOR instant per day
const FUNDS = parseEther("10");

const owner: PqcKey = generatePqcKeypair();
const guardian: PqcKey = generatePqcKeypair();
const attacker: PqcKey = generatePqcKeypair();
const pkHex = (k: PqcKey): Hex => toHexBytes(k.publicKey);

describe("QDayVault", async () => {
  const { viem, networkHelpers } = await network.create();
  const publicClient = await viem.getPublicClient();
  const [deployer, relayer, ecdsaThief, alice] = await viem.getWalletClients();
  const chainId = BigInt(await publicClient.getChainId());

  // Install the precompile test doubles once.
  const verifyImpl = await viem.deployContract("MockPQCVerify");
  const statusImpl = await viem.deployContract("MockPQCKeyStatus");
  await networkHelpers.setCode(PQC_VERIFY, (await publicClient.getCode({ address: verifyImpl.address }))!);
  await networkHelpers.setCode(PQC_STATUS, (await publicClient.getCode({ address: statusImpl.address }))!);
  const oracle = await viem.getContractAt("MockPQCVerify", PQC_VERIFY);
  const keyStatus = await viem.getContractAt("MockPQCKeyStatus", PQC_STATUS);

  async function deployVault(opts: { guardian?: boolean; ownerAccount?: Address } = {}) {
    const vault = await viem.deployContract("QDayVault", [
      pkHex(owner),
      opts.guardian === false ? "0x" : pkHex(guardian),
      opts.ownerAccount ?? NATIVE,
      LIMIT,
      DELAY,
    ]);
    await deployer.sendTransaction({ to: vault.address, value: FUNDS });
    return vault;
  }
  type Vault = Awaited<ReturnType<typeof deployVault>>;

  async function deadline(offset = 600n): Promise<bigint> {
    return BigInt(await networkHelpers.time.latest()) + offset;
  }

  /**
   * Build the message locally, check it equals the contract's own `messageFor`, sign it with
   * real ML-DSA-87 and tell the oracle mock that this exact triple is valid.
   */
  async function sign(
    vault: Vault,
    key: PqcKey,
    f: { role: number; action: number; deadline: bigint; asset?: Address; to?: Address; amount?: bigint; id?: bigint; value?: Hex; nonce?: bigint },
  ): Promise<{ pk: Hex; sig: Hex; message: Hex }> {
    const nonce = f.nonce ?? (await vault.read.nonces([f.role]));
    const message = buildMessage({ chainId, vault: vault.address, nonce, ...f });
    if (f.nonce === undefined) {
      const onChain = await vault.read.messageFor([
        f.role, f.deadline, f.action, f.asset ?? NATIVE, f.to ?? NATIVE, f.amount ?? 0n, f.id ?? 0n, f.value ?? ZERO32,
      ]);
      assert.equal(onChain, message, "contract and client must build identical message bytes");
    }
    const sig = signMessage(key, message);
    const pk = pkHex(key);
    await oracle.write.register([keccak256(encodeTriple(pk, sig, message))]);
    return { pk, sig, message };
  }

  async function withdrawSig(vault: Vault, to: Address, amount: bigint, asset: Address = NATIVE, key = owner) {
    const dl = await deadline();
    const s = await sign(vault, key, { role: Role.OWNER, action: Action.WITHDRAW, deadline: dl, asset, to, amount });
    return { dl, ...s };
  }

  const balance = (a: Address) => publicClient.getBalance({ address: a });

  // ───────────────────────────────────────────────────────────── Theorem 1
  describe("Theorem 1: a classical (ECDSA) key alone moves nothing", () => {
    it("anyone can deposit", async () => {
      const vault = await deployVault();
      assert.equal(await balance(vault.address), FUNDS);
    });

    it("a withdrawal with no valid ML-DSA signature reverts, whoever sends it", async () => {
      const vault = await deployVault();
      const dl = await deadline();
      const junkSig = `0x${"11".repeat(4627)}` as Hex;
      await viem.assertions.revertWithCustomError(
        vault.write.withdraw([NATIVE, ecdsaThief.account.address, 1n, dl, pkHex(owner), junkSig], { account: ecdsaThief.account }),
        vault,
        "BadSignature",
      );
    });

    it("a signature by the attacker's own ML-DSA key is refused (wrong key)", async () => {
      const vault = await deployVault();
      const s = await withdrawSig(vault, ecdsaThief.account.address, 1n, NATIVE, attacker);
      await viem.assertions.revertWithCustomError(
        vault.write.withdraw([NATIVE, ecdsaThief.account.address, 1n, s.dl, s.pk, s.sig], { account: ecdsaThief.account }),
        vault,
        "WrongKey",
      );
    });

    it("the owner's public key with the attacker's signature is refused", async () => {
      const vault = await deployVault();
      const s = await withdrawSig(vault, ecdsaThief.account.address, 1n, NATIVE, attacker);
      await viem.assertions.revertWithCustomError(
        vault.write.withdraw([NATIVE, ecdsaThief.account.address, 1n, s.dl, pkHex(owner), s.sig], { account: ecdsaThief.account }),
        vault,
        "BadSignature",
      );
    });

    it("every privileged function refuses a caller without the right PQ signature", async () => {
      const vault = await deployVault();
      const dl = await deadline();
      const junk = `0x${"22".repeat(4627)}` as Hex;
      const as = { account: ecdsaThief.account };
      const ok = pkHex(owner);
      await viem.assertions.revertWithCustomError(vault.write.proposeGuardianKey([pkHex(attacker), dl, ok, junk], as), vault, "BadSignature");
      await viem.assertions.revertWithCustomError(vault.write.proposeLimit([NATIVE, FUNDS, dl, ok, junk], as), vault, "BadSignature");
      await viem.assertions.revertWithCustomError(vault.write.proposeDelay([MIN_DELAY, dl, ok, junk], as), vault, "BadSignature");
      await viem.assertions.revertWithCustomError(vault.write.proposeOwnerKey([pkHex(attacker), Role.OWNER, dl, ok, junk], as), vault, "BadSignature");
      await viem.assertions.revertWithCustomError(vault.write.freeze([Role.OWNER, dl, ok, junk], as), vault, "BadSignature");
    });

    it("the vault ignores msg.sender: a valid owner signature works from any relayer, and pays only the signed recipient", async () => {
      const vault = await deployVault();
      const amount = parseEther("0.5");
      const s = await withdrawSig(vault, alice.account.address, amount);
      const before = await balance(alice.account.address);
      await vault.write.withdraw([NATIVE, alice.account.address, amount, s.dl, s.pk, s.sig], { account: relayer.account });
      assert.equal((await balance(alice.account.address)) - before, amount);
      assert.equal(await balance(vault.address), FUNDS - amount);
    });

    it("a relayer cannot redirect a signed withdrawal to itself", async () => {
      const vault = await deployVault();
      const s = await withdrawSig(vault, alice.account.address, 1n);
      await viem.assertions.revertWithCustomError(
        vault.write.withdraw([NATIVE, relayer.account.address, 1n, s.dl, s.pk, s.sig], { account: relayer.account }),
        vault,
        "BadSignature",
      );
    });
  });

  // ───────────────────────────────────────────────────────────── Theorem 2
  describe("Theorem 2: each signature authorises exactly one action, once", () => {
    it("the same signature cannot be used twice (nonce)", async () => {
      const vault = await deployVault();
      const s = await withdrawSig(vault, alice.account.address, 1n);
      await vault.write.withdraw([NATIVE, alice.account.address, 1n, s.dl, s.pk, s.sig]);
      assert.equal(await vault.read.nonces([Role.OWNER]), 1n);
      await viem.assertions.revertWithCustomError(
        vault.write.withdraw([NATIVE, alice.account.address, 1n, s.dl, s.pk, s.sig]),
        vault,
        "BadSignature",
      );
    });

    it("a signature for one vault is invalid on another vault with the same keys", async () => {
      const a = await deployVault();
      const b = await deployVault();
      const s = await withdrawSig(a, alice.account.address, 1n);
      await viem.assertions.revertWithCustomError(
        b.write.withdraw([NATIVE, alice.account.address, 1n, s.dl, s.pk, s.sig]),
        b,
        "BadSignature",
      );
    });

    it("changing any signed field (amount, asset, recipient) invalidates the signature", async () => {
      const vault = await deployVault();
      const token = await viem.deployContract("TestToken");
      const s = await withdrawSig(vault, alice.account.address, 100n);
      for (const [asset, to, amt] of [
        [NATIVE, alice.account.address, 101n],
        [token.address, alice.account.address, 100n],
        [NATIVE, relayer.account.address, 100n],
      ] as const) {
        await viem.assertions.revertWithCustomError(vault.write.withdraw([asset, to, amt, s.dl, s.pk, s.sig]), vault, "BadSignature");
      }
    });

    it("a signature for one action cannot be used for another action", async () => {
      const vault = await deployVault();
      const dl = await deadline();
      // Owner signs FREEZE; try to use it as a CANCEL and as a withdrawal.
      const s = await sign(vault, owner, { role: Role.OWNER, action: Action.FREEZE, deadline: dl });
      await viem.assertions.revertWithCustomError(
        vault.write.withdraw([NATIVE, alice.account.address, 1n, dl, s.pk, s.sig]),
        vault,
        "BadSignature",
      );
      await vault.write.freeze([Role.OWNER, dl, s.pk, s.sig]);
      assert.equal(await vault.read.frozen(), true);
    });

    it("an expired signature is refused", async () => {
      const vault = await deployVault();
      const s = await withdrawSig(vault, alice.account.address, 1n);
      await networkHelpers.time.increase(601);
      await viem.assertions.revertWithCustomError(
        vault.write.withdraw([NATIVE, alice.account.address, 1n, s.dl, s.pk, s.sig]),
        vault,
        "Expired",
      );
    });

    it("an owner signature cannot be presented as the guardian's (role is signed)", async () => {
      const vault = await deployVault();
      const dl = await deadline();
      const s = await sign(vault, owner, { role: Role.OWNER, action: Action.FREEZE, deadline: dl });
      await viem.assertions.revertWithCustomError(vault.write.freeze([Role.GUARDIAN, dl, s.pk, s.sig]), vault, "WrongKey");
    });

    it("a signature made for a future nonce is not usable now", async () => {
      const vault = await deployVault();
      const dl = await deadline();
      const s = await sign(vault, owner, { role: Role.OWNER, action: Action.FREEZE, deadline: dl, nonce: 5n });
      await viem.assertions.revertWithCustomError(vault.write.freeze([Role.OWNER, dl, s.pk, s.sig]), vault, "BadSignature");
    });
  });

  // ───────────────────────────────────────────────────────────── Lemma 3
  describe("Lemma 3: message shape (domain separation)", () => {
    it("every message is exactly 384 bytes and starts with 0xFF", async () => {
      const vault = await deployVault();
      const m = await vault.read.messageFor([Role.OWNER, 1n, Action.WITHDRAW, NATIVE, alice.account.address, 5n, 0n, ZERO32]);
      assert.equal((m.length - 2) / 2, 384);
      assert.equal(m.slice(2, 4), "ff");
    });
  });

  // ───────────────────────────────────────────────────────────── Theorem 4
  describe("Theorem 4: rate limit and delay", () => {
    it("withdrawals within the daily limit execute at once; the rest is queued", async () => {
      const vault = await deployVault();
      const half = LIMIT / 2n;
      let s = await withdrawSig(vault, alice.account.address, half);
      await vault.write.withdraw([NATIVE, alice.account.address, half, s.dl, s.pk, s.sig]);
      assert.equal(await vault.read.remainingToday([NATIVE]), half);
      assert.equal(await vault.read.itemCount(), 0n);

      s = await withdrawSig(vault, alice.account.address, LIMIT); // would exceed today's limit
      const vaultBefore = await balance(vault.address);
      await vault.write.withdraw([NATIVE, alice.account.address, LIMIT, s.dl, s.pk, s.sig]);
      assert.equal(await balance(vault.address), vaultBefore, "nothing left yet");
      assert.equal(await vault.read.itemCount(), 1n);
      const item = await vault.read.getItem([1n]);
      assert.equal(item.kind, Action.WITHDRAW);
      assert.equal(item.amount, LIMIT);
    });

    it("a queued withdrawal cannot execute before the delay, and can after it", async () => {
      const vault = await deployVault();
      const big = parseEther("5");
      const s = await withdrawSig(vault, alice.account.address, big);
      await vault.write.withdraw([NATIVE, alice.account.address, big, s.dl, s.pk, s.sig]);
      await viem.assertions.revertWithCustomError(vault.write.execute([1n], { account: relayer.account }), vault, "TooEarly");
      await networkHelpers.time.increase(Number(DELAY));
      const before = await balance(alice.account.address);
      await vault.write.execute([1n], { account: relayer.account });
      assert.equal((await balance(alice.account.address)) - before, big);
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "NotQueued");
    });

    it("the daily allowance resets on the next UTC day", async () => {
      const vault = await deployVault();
      let s = await withdrawSig(vault, alice.account.address, LIMIT);
      await vault.write.withdraw([NATIVE, alice.account.address, LIMIT, s.dl, s.pk, s.sig]);
      assert.equal(await vault.read.remainingToday([NATIVE]), 0n);
      await networkHelpers.time.increase(Number(DAY));
      assert.equal(await vault.read.remainingToday([NATIVE]), LIMIT);
      s = await withdrawSig(vault, alice.account.address, LIMIT);
      await vault.write.withdraw([NATIVE, alice.account.address, LIMIT, s.dl, s.pk, s.sig]);
      assert.equal(await vault.read.itemCount(), 0n);
    });

    it("tokens have a limit of 0 by default, so every token withdrawal is queued", async () => {
      const vault = await deployVault();
      const token = await viem.deployContract("TestToken");
      await token.write.mint([vault.address, 1000n]);
      const s = await withdrawSig(vault, alice.account.address, 10n, token.address);
      await vault.write.withdraw([token.address, alice.account.address, 10n, s.dl, s.pk, s.sig]);
      assert.equal(await token.read.balanceOf([alice.account.address]), 0n);
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([1n]);
      assert.equal(await token.read.balanceOf([alice.account.address]), 10n);
    });

    it("raising the limit is itself delayed", async () => {
      const vault = await deployVault();
      const dl = await deadline();
      const s = await sign(vault, owner, { role: Role.OWNER, action: Action.SET_LIMIT, deadline: dl, asset: NATIVE, amount: FUNDS });
      await vault.write.proposeLimit([NATIVE, FUNDS, dl, s.pk, s.sig]);
      assert.equal(await vault.read.dailyLimit([NATIVE]), LIMIT);
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([1n]);
      assert.equal(await vault.read.dailyLimit([NATIVE]), FUNDS);
    });
  });

  // ───────────────────────────────────────────────────────────── Theorem 5
  describe("Theorem 5: one stolen PQ key is not enough", () => {
    it("the guardian can cancel a queued withdrawal", async () => {
      const vault = await deployVault();
      const s = await withdrawSig(vault, ecdsaThief.account.address, parseEther("5"));
      await vault.write.withdraw([NATIVE, ecdsaThief.account.address, parseEther("5"), s.dl, s.pk, s.sig]);
      const dl = await deadline();
      const c = await sign(vault, guardian, { role: Role.GUARDIAN, action: Action.CANCEL, deadline: dl, id: 1n });
      await vault.write.cancel([1n, Role.GUARDIAN, dl, c.pk, c.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "NotQueued");
      assert.equal(await balance(vault.address), FUNDS);
    });

    it("freeze stops instant withdrawals and queued executions", async () => {
      const vault = await deployVault();
      const s1 = await withdrawSig(vault, alice.account.address, parseEther("5"));
      await vault.write.withdraw([NATIVE, alice.account.address, parseEther("5"), s1.dl, s1.pk, s1.sig]);
      const dl = await deadline();
      const f = await sign(vault, guardian, { role: Role.GUARDIAN, action: Action.FREEZE, deadline: dl });
      await vault.write.freeze([Role.GUARDIAN, dl, f.pk, f.sig]);

      const s2 = await withdrawSig(vault, alice.account.address, 1n);
      await viem.assertions.revertWithCustomError(vault.write.withdraw([NATIVE, alice.account.address, 1n, s2.dl, s2.pk, s2.sig]), vault, "IsFrozen");
      await networkHelpers.time.increase(Number(DELAY));
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "IsFrozen");
    });

    it("unfreeze needs both keys: the owner alone cannot lift it", async () => {
      const vault = await deployVault();
      let dl = await deadline();
      const f = await sign(vault, guardian, { role: Role.GUARDIAN, action: Action.FREEZE, deadline: dl });
      await vault.write.freeze([Role.GUARDIAN, dl, f.pk, f.sig]);

      dl = await deadline();
      const o = await sign(vault, owner, { role: Role.JOINT, action: Action.UNFREEZE, deadline: dl });
      const bad = await sign(vault, attacker, { role: Role.JOINT, action: Action.UNFREEZE, deadline: dl });
      await viem.assertions.revertWithCustomError(vault.write.unfreeze([dl, o.pk, o.sig, bad.pk, bad.sig]), vault, "WrongKey");
      await viem.assertions.revertWithCustomError(vault.write.unfreeze([dl, o.pk, o.sig, pkHex(guardian), bad.sig]), vault, "BadSignature");

      const g = await sign(vault, guardian, { role: Role.JOINT, action: Action.UNFREEZE, deadline: dl });
      await vault.write.unfreeze([dl, o.pk, o.sig, g.pk, g.sig]);
      assert.equal(await vault.read.frozen(), false);
    });

    it("the guardian cannot withdraw", async () => {
      const vault = await deployVault();
      const s = await withdrawSig(vault, ecdsaThief.account.address, 1n, NATIVE, guardian);
      await viem.assertions.revertWithCustomError(
        vault.write.withdraw([NATIVE, ecdsaThief.account.address, 1n, s.dl, s.pk, s.sig]),
        vault,
        "WrongKey",
      );
    });

    it("guardian recovery: a new owner key takes effect after the delay, and old pending items die", async () => {
      const vault = await deployVault();
      // The (stolen) old owner key queues a large withdrawal.
      const w = await withdrawSig(vault, ecdsaThief.account.address, parseEther("5"));
      await vault.write.withdraw([NATIVE, ecdsaThief.account.address, parseEther("5"), w.dl, w.pk, w.sig]);
      // The guardian proposes a fresh owner key.
      const fresh: PqcKey = generatePqcKeypair();
      const freshHash = keccak256(pkHex(fresh));
      const dl = await deadline();
      const p = await sign(vault, guardian, { role: Role.GUARDIAN, action: Action.SET_OWNER_KEY, deadline: dl, value: freshHash });
      await vault.write.proposeOwnerKey([pkHex(fresh), Role.GUARDIAN, dl, p.pk, p.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([2n]);
      assert.equal(await vault.read.ownerKeyHash(), freshHash);
      // The thief's withdrawal was authorised by the replaced key and can never execute.
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "StaleKey");
      // The old owner key no longer works at all.
      const old = await withdrawSig(vault, ecdsaThief.account.address, 1n);
      await viem.assertions.revertWithCustomError(vault.write.withdraw([NATIVE, ecdsaThief.account.address, 1n, old.dl, old.pk, old.sig]), vault, "WrongKey");
      // The new owner key does.
      const n = await withdrawSig(vault, alice.account.address, 1n, NATIVE, fresh);
      await vault.write.withdraw([NATIVE, alice.account.address, 1n, n.dl, n.pk, n.sig]);
    });

    it("the owner can cancel a malicious guardian's owner-key proposal", async () => {
      const vault = await deployVault();
      let dl = await deadline();
      const p = await sign(vault, guardian, { role: Role.GUARDIAN, action: Action.SET_OWNER_KEY, deadline: dl, value: keccak256(pkHex(attacker)) });
      await vault.write.proposeOwnerKey([pkHex(attacker), Role.GUARDIAN, dl, p.pk, p.sig]);
      dl = await deadline();
      const c = await sign(vault, owner, { role: Role.OWNER, action: Action.CANCEL, deadline: dl, id: 1n });
      await vault.write.cancel([1n, Role.OWNER, dl, c.pk, c.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "NotQueued");
    });

    it("the guardian cannot change limits, delay or the guardian key (owner-only signatures)", async () => {
      const vault = await deployVault();
      const dl = await deadline();
      const s = await sign(vault, guardian, { role: Role.OWNER, action: Action.SET_LIMIT, deadline: dl, asset: NATIVE, amount: FUNDS });
      await viem.assertions.revertWithCustomError(vault.write.proposeLimit([NATIVE, FUNDS, dl, s.pk, s.sig]), vault, "WrongKey");
    });
  });

  // ───────────────────────────────────────────────────────────── Lemma 7
  describe("Lemma 7: fail closed", () => {
    it("if the pqcVerify precompile is inactive (empty return data), every signed action reverts", async () => {
      const vault = await deployVault();
      const s = await withdrawSig(vault, alice.account.address, 1n);
      const code = await publicClient.getCode({ address: PQC_VERIFY });
      await networkHelpers.setCode(PQC_VERIFY, "0x");
      try {
        await viem.assertions.revertWithCustomError(
          vault.write.withdraw([NATIVE, alice.account.address, 1n, s.dl, s.pk, s.sig]),
          vault,
          "BadSignature",
        );
      } finally {
        await networkHelpers.setCode(PQC_VERIFY, code!);
      }
    });

    it("degenerate and wrong-length keys are refused at deployment", async () => {
      const degenerate = new Uint8Array(2592);
      degenerate.fill(7, 0, 32); // only rho set; t1 all zero
      await assert.rejects(viem.deployContract("QDayVault", [toHexBytes(degenerate), "0x", NATIVE, LIMIT, DELAY]));
      await assert.rejects(viem.deployContract("QDayVault", ["0x1234", "0x", NATIVE, LIMIT, DELAY]));
      await assert.rejects(viem.deployContract("QDayVault", [pkHex(owner), pkHex(owner), NATIVE, LIMIT, DELAY]));
      await assert.rejects(viem.deployContract("QDayVault", [pkHex(owner), "0x", NATIVE, LIMIT, 1n]));
    });

    it("binding to an account key requires registered + ML-DSA-87 + proof of possession + same key", async () => {
      const acct = alice.account.address;
      const pk = pkHex(owner);
      await keyStatus.write.set([acct, true, 1, pk, false]); // no proof of possession
      await assert.rejects(deployVault({ ownerAccount: acct }));
      await keyStatus.write.set([acct, true, 1, pkHex(attacker), true]); // a different key
      await assert.rejects(deployVault({ ownerAccount: acct }));
      await keyStatus.write.set([acct, true, 2, pk, true]); // wrong algorithm
      await assert.rejects(deployVault({ ownerAccount: acct }));
      await keyStatus.write.set([acct, true, 1, pk, true]);
      const vault = await deployVault({ ownerAccount: acct });
      assert.equal(await vault.read.ownerKeyHash(), keccak256(pk));
    });
  });

  // ───────────────────────────────────────────────────────────── Misc
  describe("Liveness and hygiene", () => {
    it("with no guardian, the owner alone can unfreeze", async () => {
      const vault = await deployVault({ guardian: false });
      let dl = await deadline();
      const f = await sign(vault, owner, { role: Role.OWNER, action: Action.FREEZE, deadline: dl });
      await vault.write.freeze([Role.OWNER, dl, f.pk, f.sig]);
      dl = await deadline();
      const u = await sign(vault, owner, { role: Role.JOINT, action: Action.UNFREEZE, deadline: dl });
      await vault.write.unfreeze([dl, u.pk, u.sig, "0x", "0x"]);
      assert.equal(await vault.read.frozen(), false);
    });

    it("a re-entrant recipient cannot re-enter the vault", async () => {
      const vault = await deployVault();
      const evil = await viem.deployContract("Reenterer");
      const s = await withdrawSig(vault, evil.address, parseEther("5"));
      await vault.write.withdraw([NATIVE, evil.address, parseEther("5"), s.dl, s.pk, s.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await evil.write.arm([vault.address, 1n]);
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "TransferFailed");
      assert.equal(await balance(vault.address), FUNDS);
    });

    it("a withdrawal to the zero address or a non-contract token is refused", async () => {
      const vault = await deployVault();
      const dl = await deadline();
      await viem.assertions.revertWithCustomError(
        vault.write.withdraw([NATIVE, NATIVE, 1n, dl, pkHex(owner), "0x"]),
        vault,
        "BadWithdrawal",
      );
      await viem.assertions.revertWithCustomError(
        vault.write.withdraw([alice.account.address, alice.account.address, 1n, dl, pkHex(owner), "0x"]),
        vault,
        "BadWithdrawal",
      );
    });
  });
});

const MIN_DELAY = 300n;

/** abi.encode(bytes, bytes, bytes): the key MockPQCVerify stores for a valid triple. */
function encodeTriple(pk: Hex, sig: Hex, message: Hex): Hex {
  return encodeAbiParameters([{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }], [pk, sig, message]);
}
