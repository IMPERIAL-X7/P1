/**
 * Network-agnostic vault operations used by the CLI (testnet) and by the end-to-end client
 * test (Hardhat). Every signed action:
 *   1. reads the role's nonce and the chain id,
 *   2. builds the 384-byte message LOCALLY (scripts/lib/vault.ts),
 *   3. refuses to continue if the contract's messageFor() disagrees (wrong contract or RPC),
 *   4. signs with ML-DSA-87 and submits from whatever wallet is given (the relayer).
 */
import { readFileSync } from "node:fs";
import { keccak256, type Abi, type Address, type Hex, type PublicClient, type WalletClient } from "viem";

import { Action, buildMessage, NATIVE, Role, signMessage, toHexBytes, ZERO32, type PqcKey } from "./vault.js";

const artifact = JSON.parse(
  readFileSync(new URL("../../artifacts/contracts/QDayVault.sol/QDayVault.json", import.meta.url), "utf8"),
) as { abi: Abi; bytecode: Hex };
export const VAULT_ABI = artifact.abi;
export const VAULT_BYTECODE = artifact.bytecode;

export interface Ctx {
  publicClient: PublicClient;
  walletClient: WalletClient;
  vault: Address;
  /** Optional overrides for the EVM transaction (e.g. a fee cap that fits an EVM window). */
  tx?: { gas?: bigint; maxFeePerGas?: bigint; maxPriorityFeePerGas?: bigint };
  /** Test hook: called with every signature before it is submitted (unused on testnet). */
  onSigned?: (pk: Hex, sig: Hex, message: Hex) => Promise<void>;
}

interface Fields {
  action: number;
  asset?: Address;
  to?: Address;
  amount?: bigint;
  id?: bigint;
  value?: Hex;
}

const read = <T>(c: Ctx, functionName: string, args: unknown[] = []) =>
  c.publicClient.readContract({ address: c.vault, abi: VAULT_ABI, functionName, args }) as Promise<T>;

/** Build, cross-check and sign the message for `role`'s next action. */
export async function signFor(c: Ctx, key: PqcKey, role: number, f: Fields, ttlSeconds = 600n) {
  const [nonce, chainId, block] = await Promise.all([
    read<bigint>(c, "nonces", [role]),
    c.publicClient.getChainId(),
    c.publicClient.getBlock(),
  ]);
  const deadline = block.timestamp + ttlSeconds;
  const message = buildMessage({ chainId: BigInt(chainId), vault: c.vault, role, nonce, deadline, ...f });
  const onChain = await read<Hex>(c, "messageFor", [
    role, deadline, f.action, f.asset ?? NATIVE, f.to ?? NATIVE, f.amount ?? 0n, f.id ?? 0n, f.value ?? ZERO32,
  ]);
  if (onChain.toLowerCase() !== message.toLowerCase()) {
    throw new Error("messageFor() differs from the locally built message: wrong contract or untrusted RPC. Not signing.");
  }
  const out = { deadline, pk: toHexBytes(key.publicKey), sig: signMessage(key, message), message };
  await c.onSigned?.(out.pk, out.sig, message);
  return out;
}

async function send(c: Ctx, functionName: string, args: unknown[]): Promise<Hex> {
  const account = c.walletClient.account!;
  const { request } = await c.publicClient.simulateContract({
    address: c.vault,
    abi: VAULT_ABI,
    functionName,
    args,
    account,
    ...c.tx,
  });
  const hash = await c.walletClient.writeContract(request);
  const receipt = await c.publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error(`${functionName} reverted: ${hash}`);
  return hash;
}

export async function withdraw(c: Ctx, owner: PqcKey, to: Address, amount: bigint, asset: Address = NATIVE) {
  const s = await signFor(c, owner, Role.OWNER, { action: Action.WITHDRAW, asset, to, amount });
  return send(c, "withdraw", [asset, to, amount, s.deadline, s.pk, s.sig]);
}

export async function proposeLimit(c: Ctx, owner: PqcKey, asset: Address, limit: bigint) {
  const s = await signFor(c, owner, Role.OWNER, { action: Action.SET_LIMIT, asset, amount: limit });
  return send(c, "proposeLimit", [asset, limit, s.deadline, s.pk, s.sig]);
}

export async function proposeDelay(c: Ctx, owner: PqcKey, delay: bigint) {
  const s = await signFor(c, owner, Role.OWNER, { action: Action.SET_DELAY, amount: delay });
  return send(c, "proposeDelay", [delay, s.deadline, s.pk, s.sig]);
}

export async function proposeGuardianKey(c: Ctx, owner: PqcKey, newGuardianPk: Uint8Array | null) {
  const value = newGuardianPk ? keccak256(toHexBytes(newGuardianPk)) : ZERO32;
  const s = await signFor(c, owner, Role.OWNER, { action: Action.SET_GUARDIAN_KEY, value });
  return send(c, "proposeGuardianKey", [newGuardianPk ? toHexBytes(newGuardianPk) : "0x", s.deadline, s.pk, s.sig]);
}

export async function proposeOwnerKey(c: Ctx, signer: PqcKey, role: number, newOwnerPk: Uint8Array) {
  const value = keccak256(toHexBytes(newOwnerPk));
  const s = await signFor(c, signer, role, { action: Action.SET_OWNER_KEY, value });
  return send(c, "proposeOwnerKey", [toHexBytes(newOwnerPk), role, s.deadline, s.pk, s.sig]);
}

export async function cancel(c: Ctx, signer: PqcKey, role: number, id: bigint) {
  const s = await signFor(c, signer, role, { action: Action.CANCEL, id });
  return send(c, "cancel", [id, role, s.deadline, s.pk, s.sig]);
}

export async function freeze(c: Ctx, signer: PqcKey, role: number) {
  const s = await signFor(c, signer, role, { action: Action.FREEZE });
  return send(c, "freeze", [role, s.deadline, s.pk, s.sig]);
}

export async function unfreeze(c: Ctx, owner: PqcKey, guardian: PqcKey | null) {
  const o = await signFor(c, owner, Role.JOINT, { action: Action.UNFREEZE });
  // Both keys sign the very same message (same nonce and deadline).
  const gSig = guardian ? signMessage(guardian, o.message) : "0x";
  const gPk = guardian ? toHexBytes(guardian.publicKey) : "0x";
  if (guardian) await c.onSigned?.(gPk, gSig, o.message);
  return send(c, "unfreeze", [o.deadline, o.pk, o.sig, gPk, gSig]);
}

export async function execute(c: Ctx, id: bigint) {
  return send(c, "execute", [id]);
}

export interface VaultStatus {
  balance: bigint;
  frozen: boolean;
  delay: bigint;
  nativeLimit: bigint;
  remainingToday: bigint;
  ownerKeyHash: Hex;
  guardianKeyHash: Hex;
  nonces: { owner: bigint; guardian: bigint; joint: bigint };
  items: { id: bigint; kind: number; status: number; signerRole: number; eta: bigint; asset: Address; to: Address; amount: bigint; value: Hex }[];
}

export async function status(c: Ctx): Promise<VaultStatus> {
  const count = await read<bigint>(c, "itemCount");
  const items = [];
  for (let id = 1n; id <= count; id++) {
    const it = await read<VaultStatus["items"][number]>(c, "getItem", [id]);
    items.push({ ...it, id });
  }
  return {
    balance: await c.publicClient.getBalance({ address: c.vault }),
    frozen: await read<boolean>(c, "frozen"),
    delay: await read<bigint>(c, "delay"),
    nativeLimit: await read<bigint>(c, "dailyLimit", [NATIVE]),
    remainingToday: await read<bigint>(c, "remainingToday", [NATIVE]),
    ownerKeyHash: await read<Hex>(c, "ownerKeyHash"),
    guardianKeyHash: await read<Hex>(c, "guardianKeyHash"),
    nonces: {
      owner: await read<bigint>(c, "nonces", [Role.OWNER]),
      guardian: await read<bigint>(c, "nonces", [Role.GUARDIAN]),
      joint: await read<bigint>(c, "nonces", [Role.JOINT]),
    },
    items,
  };
}
