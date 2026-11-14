/**
 * Adversarial and edge-case tests, plus an end-to-end run of the CLI's client library
 * (scripts/lib/ops.ts) against a local chain. Same signature model as test/QDayVault.ts:
 * real ML-DSA-87 signatures, an oracle mock at the precompile address.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { encodeAbiParameters, keccak256, parseEther, type Address, type Hex, type PublicClient, type WalletClient } from "viem";
import { generatePqcKeypair } from "@qorechain/sdk";

import { Action, buildMessage, NATIVE, Role, signMessage, toHexBytes, ZERO32, type PqcKey } from "../scripts/lib/vault.js";
import * as ops from "../scripts/lib/ops.js";

const PQC_VERIFY: Address = "0x0000000000000000000000000000000000000a01";
const PQC_STATUS: Address = "0x0000000000000000000000000000000000000a02";
const DELAY = 3_600n;
const LIMIT = parseEther("1");
const FUNDS = parseEther("10");

const owner: PqcKey = generatePqcKeypair();
const guardian: PqcKey = generatePqcKeypair();
const attacker: PqcKey = generatePqcKeypair();
const pkHex = (k: PqcKey): Hex => toHexBytes(k.publicKey);
const triple = (pk: Hex, sig: Hex, m: Hex) =>
  keccak256(encodeAbiParameters([{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }], [pk, sig, m]));

describe("Adversarial", async () => {
  const { viem, networkHelpers } = await network.create();
  const publicClient = await viem.getPublicClient();
  const [deployer, relayer, thief, alice, bob] = await viem.getWalletClients();
  const chainId = BigInt(await publicClient.getChainId());

  const verifyImpl = await viem.deployContract("MockPQCVerify");
  const oracleCode = (await publicClient.getCode({ address: verifyImpl.address }))!;
  await networkHelpers.setCode(PQC_VERIFY, oracleCode);
  const statusImpl = await viem.deployContract("MockPQCKeyStatus");
  await networkHelpers.setCode(PQC_STATUS, (await publicClient.getCode({ address: statusImpl.address }))!);
  const oracle = await viem.getContractAt("MockPQCVerify", PQC_VERIFY);

  async function deployVault(guardianPk: Hex = pkHex(guardian)) {
    const vault = await viem.deployContract("QDayVault", [pkHex(owner), guardianPk, NATIVE, LIMIT, DELAY]);
    await deployer.sendTransaction({ to: vault.address, value: FUNDS });
    return vault;
  }
  type Vault = Awaited<ReturnType<typeof deployVault>>;
  const now = async () => BigInt(await networkHelpers.time.latest());
  const bal = (a: Address) => publicClient.getBalance({ address: a });

  async function sign(
    vault: Vault,
    key: PqcKey,
    f: { role: number; action: number; asset?: Address; to?: Address; amount?: bigint; id?: bigint; value?: Hex; deadline?: bigint; chainId?: bigint; nonce?: bigint },
  ) {
    const deadline = f.deadline ?? (await now()) + 600n;
    const nonce = f.nonce ?? (await vault.read.nonces([f.role]));
    const message = buildMessage({ chainId: f.chainId ?? chainId, vault: vault.address, nonce, deadline, ...f });
    const sig = signMessage(key, message);
    await oracle.write.register([triple(pkHex(key), sig, message)]);
    return { deadline, pk: pkHex(key), sig, message };
  }
  const W = (vault: Vault, to: Address, amount: bigint, key = owner, extra: { chainId?: bigint; deadline?: bigint } = {}) =>
    sign(vault, key, { role: Role.OWNER, action: Action.WITHDRAW, to, amount, ...extra });

  describe("replay and binding", () => {
    it("a signature over another chain id is refused", async () => {
      const vault = await deployVault();
      const s = await W(vault, alice.account.address, 1n, owner, { chainId: chainId + 1n });
      await viem.assertions.revertWithCustomError(vault.write.withdraw([NATIVE, alice.account.address, 1n, s.deadline, s.pk, s.sig]), vault, "BadSignature");
    });

    it("a joint (unfreeze) signature cannot be used as an owner freeze or withdrawal", async () => {
      const vault = await deployVault();
      const j = await sign(vault, owner, { role: Role.JOINT, action: Action.UNFREEZE });
      await viem.assertions.revertWithCustomError(vault.write.freeze([Role.OWNER, j.deadline, j.pk, j.sig]), vault, "BadSignature");
    });

    it("unfreeze cannot be replayed after a second freeze", async () => {
      const vault = await deployVault();
      const f1 = await sign(vault, guardian, { role: Role.GUARDIAN, action: Action.FREEZE });
      await vault.write.freeze([Role.GUARDIAN, f1.deadline, f1.pk, f1.sig]);
      const o = await sign(vault, owner, { role: Role.JOINT, action: Action.UNFREEZE });
      const g = signMessage(guardian, o.message);
      await oracle.write.register([triple(pkHex(guardian), g, o.message)]);
      await vault.write.unfreeze([o.deadline, o.pk, o.sig, pkHex(guardian), g]);
      const f2 = await sign(vault, guardian, { role: Role.GUARDIAN, action: Action.FREEZE });
      await vault.write.freeze([Role.GUARDIAN, f2.deadline, f2.pk, f2.sig]);
      await viem.assertions.revertWithCustomError(vault.write.unfreeze([o.deadline, o.pk, o.sig, pkHex(guardian), g]), vault, "BadSignature");
      assert.equal(await vault.read.frozen(), true);
    });

    it("unfreeze when not frozen is refused", async () => {
      const vault = await deployVault();
      await viem.assertions.revertWithCustomError(vault.write.unfreeze([0n, "0x", "0x", "0x", "0x"]), vault, "NotFrozen");
    });

    it("a deadline equal to the block time is accepted; one second later it is not", async () => {
      const vault = await deployVault();
      const t = (await now()) + 100n;
      const s = await W(vault, alice.account.address, 1n, owner, { deadline: t });
      await networkHelpers.time.setNextBlockTimestamp(t);
      await vault.write.withdraw([NATIVE, alice.account.address, 1n, s.deadline, s.pk, s.sig]);
      const s2 = await W(vault, alice.account.address, 1n, owner, { deadline: t });
      await viem.assertions.revertWithCustomError(vault.write.withdraw([NATIVE, alice.account.address, 1n, s2.deadline, s2.pk, s2.sig]), vault, "Expired");
    });
  });

  describe("mempool attacks", () => {
    it("front-running a signed withdrawal only does what the owner signed, once", async () => {
      const vault = await deployVault();
      const amt = parseEther("0.3");
      const s = await W(vault, alice.account.address, amt);
      const before = await bal(alice.account.address);
      // The thief copies the pending transaction and gets it in first.
      await vault.write.withdraw([NATIVE, alice.account.address, amt, s.deadline, s.pk, s.sig], { account: thief.account });
      // The owner's own copy now fails: nothing is paid twice.
      await viem.assertions.revertWithCustomError(
        vault.write.withdraw([NATIVE, alice.account.address, amt, s.deadline, s.pk, s.sig], { account: relayer.account }),
        vault,
        "BadSignature",
      );
      assert.equal((await bal(alice.account.address)) - before, amt);
    });

    it("a relayer that sends too little gas only wastes its own gas: the nonce is not consumed", async () => {
      const vault = await deployVault();
      const s = await W(vault, alice.account.address, 1n);
      await assert.rejects(
        vault.write.withdraw([NATIVE, alice.account.address, 1n, s.deadline, s.pk, s.sig], { account: relayer.account, gas: 60_000n }),
      );
      assert.equal(await vault.read.nonces([Role.OWNER]), 0n);
      await vault.write.withdraw([NATIVE, alice.account.address, 1n, s.deadline, s.pk, s.sig]);
      assert.equal(await vault.read.nonces([Role.OWNER]), 1n);
    });
  });

  describe("queue lifecycle", () => {
    it("ids that do not exist, executed or cancelled items cannot be cancelled or executed", async () => {
      const vault = await deployVault();
      const c0 = await sign(vault, owner, { role: Role.OWNER, action: Action.CANCEL, id: 0n });
      await viem.assertions.revertWithCustomError(vault.write.cancel([0n, Role.OWNER, c0.deadline, c0.pk, c0.sig]), vault, "NotQueued");
      await viem.assertions.revertWithCustomError(vault.write.execute([0n]), vault, "NotQueued");
      await viem.assertions.revertWithCustomError(vault.write.execute([7n]), vault, "NotQueued");

      const w = await W(vault, alice.account.address, parseEther("5"));
      await vault.write.withdraw([NATIVE, alice.account.address, parseEther("5"), w.deadline, w.pk, w.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([1n]);
      const c1 = await sign(vault, owner, { role: Role.OWNER, action: Action.CANCEL, id: 1n });
      await viem.assertions.revertWithCustomError(vault.write.cancel([1n, Role.OWNER, c1.deadline, c1.pk, c1.sig]), vault, "NotQueued");
    });

    it("a delay change only affects items queued after it", async () => {
      const vault = await deployVault();
      const w = await W(vault, alice.account.address, parseEther("5"));
      await vault.write.withdraw([NATIVE, alice.account.address, parseEther("5"), w.deadline, w.pk, w.sig]);
      const eta1 = (await vault.read.getItem([1n])).eta;
      const d = await sign(vault, owner, { role: Role.OWNER, action: Action.SET_DELAY, amount: 7n * 86_400n });
      await vault.write.proposeDelay([7n * 86_400n, d.deadline, d.pk, d.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([2n]);
      assert.equal(await vault.read.delay(), 7n * 86_400n);
      assert.equal((await vault.read.getItem([1n])).eta, eta1);
      await vault.write.execute([1n]); // still executable on its original schedule
    });

    it("exactly the remaining allowance is instant; one more wei is queued; lowering the limit takes effect", async () => {
      const vault = await deployVault();
      let s = await W(vault, alice.account.address, LIMIT);
      await vault.write.withdraw([NATIVE, alice.account.address, LIMIT, s.deadline, s.pk, s.sig]);
      assert.equal(await vault.read.itemCount(), 0n);
      s = await W(vault, alice.account.address, 1n);
      await vault.write.withdraw([NATIVE, alice.account.address, 1n, s.deadline, s.pk, s.sig]);
      assert.equal(await vault.read.itemCount(), 1n);
      const l = await sign(vault, owner, { role: Role.OWNER, action: Action.SET_LIMIT, asset: NATIVE, amount: 0n });
      await vault.write.proposeLimit([NATIVE, 0n, l.deadline, l.pk, l.sig]);
      await networkHelpers.time.increase(86_400);
      await vault.write.execute([2n]);
      s = await W(vault, alice.account.address, 1n);
      await vault.write.withdraw([NATIVE, alice.account.address, 1n, s.deadline, s.pk, s.sig]);
      assert.equal(await vault.read.itemCount(), 3n, "with limit 0 everything is queued");
    });

    it("an absurd amount is queued, and its execution fails without side effects", async () => {
      const vault = await deployVault();
      const max = 2n ** 256n - 1n;
      const s = await W(vault, alice.account.address, max);
      await vault.write.withdraw([NATIVE, alice.account.address, max, s.deadline, s.pk, s.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "TransferFailed");
      assert.equal(await bal(vault.address), FUNDS);
      assert.equal((await vault.read.getItem([1n])).status, 1, "still queued; can be cancelled");
    });
  });

  describe("key changes (Lemma 6)", () => {
    it("replacing the guardian kills every item the old guardian queued", async () => {
      const vault = await deployVault();
      // A (stolen) guardian queues an owner-key change to the attacker's key.
      const p = await sign(vault, guardian, { role: Role.GUARDIAN, action: Action.SET_OWNER_KEY, value: keccak256(pkHex(attacker)) });
      await vault.write.proposeOwnerKey([pkHex(attacker), Role.GUARDIAN, p.deadline, p.pk, p.sig]);
      // The owner replaces the guardian with a fresh key.
      const fresh = generatePqcKeypair();
      const g = await sign(vault, owner, { role: Role.OWNER, action: Action.SET_GUARDIAN_KEY, value: keccak256(pkHex(fresh)) });
      await vault.write.proposeGuardianKey([pkHex(fresh), g.deadline, g.pk, g.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([2n]); // the guardian change lands first
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "StaleKey");
      assert.equal(await vault.read.ownerKeyHash(), keccak256(pkHex(owner)));
    });

    it("swapping a key away and back does not revive its old items", async () => {
      const vault = await deployVault();
      const p = await sign(vault, guardian, { role: Role.GUARDIAN, action: Action.SET_OWNER_KEY, value: keccak256(pkHex(attacker)) });
      await vault.write.proposeOwnerKey([pkHex(attacker), Role.GUARDIAN, p.deadline, p.pk, p.sig]); // #1, by the old guardian
      const fresh = generatePqcKeypair();
      let g = await sign(vault, owner, { role: Role.OWNER, action: Action.SET_GUARDIAN_KEY, value: keccak256(pkHex(fresh)) });
      await vault.write.proposeGuardianKey([pkHex(fresh), g.deadline, g.pk, g.sig]); // #2
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([2n]);
      g = await sign(vault, owner, { role: Role.OWNER, action: Action.SET_GUARDIAN_KEY, value: keccak256(pkHex(guardian)) });
      await vault.write.proposeGuardianKey([pkHex(guardian), g.deadline, g.pk, g.sig]); // #3: back to the old key
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([3n]);
      assert.equal(await vault.read.guardianKeyHash(), keccak256(pkHex(guardian)));
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "StaleKey");
    });

    it("an owner rotation kills the owner's other pending items", async () => {
      const vault = await deployVault();
      const w = await W(vault, alice.account.address, parseEther("5"));
      await vault.write.withdraw([NATIVE, alice.account.address, parseEther("5"), w.deadline, w.pk, w.sig]);
      const fresh = generatePqcKeypair();
      const r = await sign(vault, owner, { role: Role.OWNER, action: Action.SET_OWNER_KEY, value: keccak256(pkHex(fresh)) });
      await vault.write.proposeOwnerKey([pkHex(fresh), Role.OWNER, r.deadline, r.pk, r.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([2n]);
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "StaleKey");
    });

    it("the guardian can be removed; afterwards guardian signatures fail and the owner unfreezes alone", async () => {
      const vault = await deployVault();
      const g = await sign(vault, owner, { role: Role.OWNER, action: Action.SET_GUARDIAN_KEY, value: ZERO32 });
      await vault.write.proposeGuardianKey(["0x", g.deadline, g.pk, g.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([1n]);
      assert.equal(await vault.read.guardianKeyHash(), ZERO32);
      const f = await sign(vault, guardian, { role: Role.GUARDIAN, action: Action.FREEZE });
      await viem.assertions.revertWithCustomError(vault.write.freeze([Role.GUARDIAN, f.deadline, f.pk, f.sig]), vault, "WrongKey");
    });

    it("keys can never become equal: owner = guardian is refused at execution", async () => {
      const vault = await deployVault();
      const p = await sign(vault, owner, { role: Role.OWNER, action: Action.SET_GUARDIAN_KEY, value: keccak256(pkHex(owner)) });
      await vault.write.proposeGuardianKey([pkHex(owner), p.deadline, p.pk, p.sig]);
      const q = await sign(vault, owner, { role: Role.OWNER, action: Action.SET_OWNER_KEY, value: keccak256(pkHex(guardian)) });
      await vault.write.proposeOwnerKey([pkHex(guardian), Role.OWNER, q.deadline, q.pk, q.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "SameKeys");
      await viem.assertions.revertWithCustomError(vault.write.execute([2n]), vault, "SameKeys");
    });

    it("a degenerate or short new key is refused at proposal time", async () => {
      const vault = await deployVault();
      const degenerate = new Uint8Array(2592);
      degenerate.fill(9, 0, 32);
      const dl = (await now()) + 600n;
      await viem.assertions.revertWithCustomError(vault.write.proposeOwnerKey([toHexBytes(degenerate), Role.OWNER, dl, pkHex(owner), "0x"]), vault, "BadKey");
      await viem.assertions.revertWithCustomError(vault.write.proposeGuardianKey(["0x1234", dl, pkHex(owner), "0x"]), vault, "BadKey");
    });
  });

  describe("liveness (Theorem 8)", () => {
    it("frozen vault + lost guardian key: owner installs a new guardian, then unfreezes with it", async () => {
      const vault = await deployVault();
      const f = await sign(vault, owner, { role: Role.OWNER, action: Action.FREEZE });
      await vault.write.freeze([Role.OWNER, f.deadline, f.pk, f.sig]);
      const fresh = generatePqcKeypair();
      const g = await sign(vault, owner, { role: Role.OWNER, action: Action.SET_GUARDIAN_KEY, value: keccak256(pkHex(fresh)) });
      await vault.write.proposeGuardianKey([pkHex(fresh), g.deadline, g.pk, g.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([1n]); // settings changes still execute while frozen
      const o = await sign(vault, owner, { role: Role.JOINT, action: Action.UNFREEZE });
      const gs = signMessage(fresh, o.message);
      await oracle.write.register([triple(pkHex(fresh), gs, o.message)]);
      await vault.write.unfreeze([o.deadline, o.pk, o.sig, pkHex(fresh), gs]);
      assert.equal(await vault.read.frozen(), false);
    });
  });

  describe("fail closed (Lemma 7)", () => {
    for (const name of ["GarbageVerify", "LongTrueVerify"] as const) {
      it(`a precompile answering in an unexpected format (${name}) is treated as invalid`, async () => {
        const vault = await deployVault();
        const s = await W(vault, alice.account.address, 1n);
        const impl = await viem.deployContract(name);
        await networkHelpers.setCode(PQC_VERIFY, (await publicClient.getCode({ address: impl.address }))!);
        try {
          await viem.assertions.revertWithCustomError(vault.write.withdraw([NATIVE, alice.account.address, 1n, s.deadline, s.pk, s.sig]), vault, "BadSignature");
        } finally {
          await networkHelpers.setCode(PQC_VERIFY, oracleCode);
        }
      });
    }

    it("binding to an account when pqcKeyStatus is inactive fails deployment", async () => {
      const code = await publicClient.getCode({ address: PQC_STATUS });
      await networkHelpers.setCode(PQC_STATUS, "0x");
      try {
        await assert.rejects(viem.deployContract("QDayVault", [pkHex(owner), pkHex(guardian), alice.account.address, LIMIT, DELAY]));
      } finally {
        await networkHelpers.setCode(PQC_STATUS, code!);
      }
    });
  });

  describe("tokens", () => {
    it("a token whose transfer returns false is treated as a failed transfer", async () => {
      const vault = await deployVault();
      const tok = await viem.deployContract("FalseToken");
      const s = await sign(vault, owner, { role: Role.OWNER, action: Action.WITHDRAW, asset: tok.address, to: alice.account.address, amount: 5n });
      await vault.write.withdraw([tok.address, alice.account.address, 5n, s.deadline, s.pk, s.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await viem.assertions.revertWithCustomError(vault.write.execute([1n]), vault, "TransferFailed");
    });

    it("a token whose transfer returns nothing (USDT-style) works", async () => {
      const vault = await deployVault();
      const tok = await viem.deployContract("NoReturnToken");
      await tok.write.mint([vault.address, 100n]);
      const s = await sign(vault, owner, { role: Role.OWNER, action: Action.WITHDRAW, asset: tok.address, to: bob.account.address, amount: 40n });
      await vault.write.withdraw([tok.address, bob.account.address, 40n, s.deadline, s.pk, s.sig]);
      await networkHelpers.time.increase(Number(DELAY));
      await vault.write.execute([1n]);
      assert.equal(await tok.read.balanceOf([bob.account.address]), 40n);
    });
  });

  describe("CLI client library end to end (scripts/lib/ops.ts)", () => {
    async function ctx(vault: Vault, wallet: WalletClient, pc: PublicClient = publicClient as unknown as PublicClient): Promise<ops.Ctx> {
      return {
        publicClient: pc,
        walletClient: wallet,
        vault: vault.address,
        onSigned: async (pk, sig, m) => {
          await oracle.write.register([triple(pk, sig, m)]);
        },
      };
    }

    it("full lifecycle through the client: instant, queue, guardian cancel, freeze, joint unfreeze, recovery", async () => {
      const vault = await deployVault();
      const c = await ctx(vault, relayer as unknown as WalletClient);
      const a = alice.account.address;

      const before = await bal(a);
      await ops.withdraw(c, owner, a, parseEther("0.25"));
      assert.equal((await bal(a)) - before, parseEther("0.25"));

      await ops.withdraw(c, owner, a, parseEther("5")); // queued as #1
      await ops.cancel(c, guardian, Role.GUARDIAN, 1n);
      await ops.withdraw(c, owner, a, parseEther("5")); // queued as #2
      await networkHelpers.time.increase(Number(DELAY));
      await ops.execute(c, 2n);

      await ops.freeze(c, guardian, Role.GUARDIAN);
      await assert.rejects(ops.withdraw(c, owner, a, 1n));
      await ops.unfreeze(c, owner, guardian);

      const fresh = generatePqcKeypair();
      await ops.proposeOwnerKey(c, guardian, Role.GUARDIAN, fresh.publicKey); // #3
      await networkHelpers.time.increase(Number(DELAY));
      await ops.execute(c, 3n);
      await assert.rejects(ops.withdraw(c, owner, a, 1n)); // old key is dead
      await ops.withdraw(c, fresh, a, 1n);

      const s = await ops.status(c);
      assert.equal(s.frozen, false);
      assert.equal(s.items.length, 3);
      assert.deepEqual(s.items.map((i) => i.status), [3, 2, 2]);
      assert.equal(s.ownerKeyHash, keccak256(pkHex(fresh)));
    });

    it("the client refuses to sign when the contract's message differs from its own (wrong chain / lying RPC)", async () => {
      const vault = await deployVault();
      const lying = new Proxy(publicClient as unknown as PublicClient, {
        get(target, prop, recv) {
          if (prop === "getChainId") return async () => 1;
          return Reflect.get(target, prop, recv);
        },
      });
      const c = await ctx(vault, relayer as unknown as WalletClient, lying);
      await assert.rejects(ops.withdraw(c, owner, alice.account.address, 1n), /differs/);
    });

    it("the client's guardian-key, limit and delay proposals round-trip", async () => {
      const vault = await deployVault();
      const c = await ctx(vault, relayer as unknown as WalletClient);
      await ops.proposeLimit(c, owner, NATIVE, parseEther("2"));
      await ops.proposeDelay(c, owner, 7_200n);
      await ops.proposeGuardianKey(c, owner, null);
      await networkHelpers.time.increase(Number(DELAY));
      for (const id of [1n, 2n, 3n]) await ops.execute(c, id);
      const s = await ops.status(c);
      assert.equal(s.nativeLimit, parseEther("2"));
      assert.equal(s.delay, 7_200n);
      assert.equal(s.guardianKeyHash, ZERO32);
    });
  });

  describe("message format cross-check (property)", () => {
    it("200 random field tuples: the TypeScript builder and the contract agree byte for byte", async () => {
      const vault = await deployVault();
      const rnd = (bytes: number) => BigInt(`0x${Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("hex")}`);
      const addr = () => `0x${rnd(20).toString(16).padStart(40, "0")}` as Address;
      for (let i = 0; i < 200; i++) {
        const role = Number(rnd(1));
        const f = {
          role,
          deadline: rnd(8),
          action: Number(rnd(1)),
          asset: addr(),
          to: addr(),
          amount: rnd(32),
          id: rnd(32),
          value: `0x${rnd(32).toString(16).padStart(64, "0")}` as Hex,
        };
        const nonce = await vault.read.nonces([role]);
        const local = buildMessage({ chainId, vault: vault.address, nonce, ...f });
        const remote = await vault.read.messageFor([f.role, f.deadline, f.action, f.asset, f.to, f.amount, f.id, f.value]);
        assert.equal(remote, local);
      }
    });
  });
});
