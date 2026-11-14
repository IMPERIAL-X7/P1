/**
 * Off-chain side of the Q-Day Vault message format (docs/SECURITY_PROOFS.md §4.1).
 * This is an independent implementation of `QDayVault._message`; the tests check that
 * both produce identical bytes, so a client never has to trust the contract's `messageFor`.
 */
import { encodeAbiParameters, hexToBytes, type Address, type Hex } from "viem";
import { pqcSign, pqcVerify } from "@qorechain/sdk";

export const DOMAIN_TAG: Hex = "0xff514441592d5641554c542d7631000000000000000000000000000000000000";
export const NATIVE: Address = "0x0000000000000000000000000000000000000000";
export const ZERO32: Hex = "0x0000000000000000000000000000000000000000000000000000000000000000";

export const Role = { OWNER: 1, GUARDIAN: 2, JOINT: 3 } as const;
export const Action = {
  WITHDRAW: 1,
  SET_OWNER_KEY: 2,
  SET_GUARDIAN_KEY: 3,
  SET_LIMIT: 4,
  SET_DELAY: 5,
  CANCEL: 6,
  FREEZE: 7,
  UNFREEZE: 8,
} as const;

export interface MessageFields {
  chainId: bigint;
  vault: Address;
  role: number;
  nonce: bigint;
  deadline: bigint;
  action: number;
  asset?: Address;
  to?: Address;
  amount?: bigint;
  id?: bigint;
  value?: Hex;
}

/** The 384-byte message: 12 static ABI words, in this exact order. */
export function buildMessage(f: MessageFields): Hex {
  return encodeAbiParameters(
    [
      { type: "bytes32" }, // DOMAIN_TAG
      { type: "uint256" }, // chain id
      { type: "address" }, // vault
      { type: "uint8" }, // role
      { type: "uint256" }, // nonce
      { type: "uint64" }, // deadline
      { type: "uint8" }, // action
      { type: "address" }, // asset
      { type: "address" }, // to
      { type: "uint256" }, // amount
      { type: "uint256" }, // id
      { type: "bytes32" }, // value
    ],
    [
      DOMAIN_TAG,
      f.chainId,
      f.vault,
      f.role,
      f.nonce,
      f.deadline,
      f.action,
      f.asset ?? NATIVE,
      f.to ?? NATIVE,
      f.amount ?? 0n,
      f.id ?? 0n,
      f.value ?? ZERO32,
    ],
  );
}

export interface PqcKey {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Sign the raw message bytes with ML-DSA-87 (FIPS-204, empty context), as the precompile expects. */
export function signMessage(key: PqcKey, message: Hex): Hex {
  const bytes = hexToBytes(message);
  const sig = pqcSign(key.secretKey, bytes);
  if (!pqcVerify(key.publicKey, bytes, sig)) throw new Error("local ML-DSA self-check failed");
  return toHexBytes(sig);
}

export function toHexBytes(b: Uint8Array): Hex {
  return `0x${Buffer.from(b).toString("hex")}`;
}
