/**
 * QoreChain plumbing for the CLI: network constants, the account from .env, the guardian
 * key file, native-lane (hybrid) broadcasting and viem clients for the EVM lane.
 * Native-lane helpers follow scripts/window.ts from qorechain/build-before-qday (Apache-2.0).
 */
import { existsSync, readFileSync } from "node:fs";
import { StargateClient } from "@cosmjs/stargate";
import {
  EthNativeSigner,
  isValidRecoveryCode,
  unifiedAccountFromSeed,
  type UnifiedAccount,
} from "@qorechain/sdk";
import { createPublicClient, createWalletClient, defineChain, http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import type { PqcKey } from "./vault.js";

export const NET = {
  chainId: "qorechain-diana",
  evmChainId: 9800,
  rest: "https://api-testnet.qore.host",
  rpc: "https://rpc-testnet.qore.host",
  evm: "https://evm-testnet.qore.host",
  explorer: "https://explore.qore.network",
} as const;

export const qoreTestnet = defineChain({
  id: NET.evmChainId,
  name: "QoreChain Testnet",
  nativeCurrency: { name: "QOR", symbol: "QOR", decimals: 18 },
  rpcUrls: { default: { http: [NET.evm] } },
  blockExplorers: { default: { name: "QoreChain Explorer", url: NET.explorer } },
});

export const GUARDIAN_FILE = "secrets/guardian.json";
export const DEPLOYMENT_FILE = "deployments/testnet.json";

/** The drill account: a raw ECDSA key plus a separate recovery code for the ML-DSA-87 key. */
export function loadAccount(): UnifiedAccount {
  const key = process.env.PRIVATE_KEY?.trim();
  const code = process.env.QORE_PQC_RECOVERY_CODE?.trim();
  if (!key || !/^0x[0-9a-fA-F]{64}$/.test(key)) throw new Error("PRIVATE_KEY missing or malformed in .env (run: npm run vault -- init)");
  if (!code || !isValidRecoveryCode(code)) throw new Error("QORE_PQC_RECOVERY_CODE missing or invalid in .env");
  return unifiedAccountFromSeed(Uint8Array.from(Buffer.from(key.slice(2), "hex")), { recoveryCode: code });
}

export function loadGuardian(): PqcKey {
  if (!existsSync(GUARDIAN_FILE)) throw new Error(`${GUARDIAN_FILE} not found (run: npm run vault -- init)`);
  const j = JSON.parse(readFileSync(GUARDIAN_FILE, "utf8")) as { publicKey: string; secretKey: string };
  return { publicKey: Buffer.from(j.publicKey, "hex"), secretKey: Buffer.from(j.secretKey, "hex") };
}

export function loadDeployment(): { vault: Hex } {
  if (!existsSync(DEPLOYMENT_FILE)) throw new Error(`${DEPLOYMENT_FILE} not found (run: npm run vault -- deploy)`);
  return JSON.parse(readFileSync(DEPLOYMENT_FILE, "utf8")) as { vault: Hex };
}

export function clients(acc: UnifiedAccount) {
  const transport = http(NET.evm);
  const publicClient = createPublicClient({ chain: qoreTestnet, transport });
  const walletClient = createWalletClient({
    chain: qoreTestnet,
    transport,
    account: privateKeyToAccount(acc.privateKey as Hex),
  });
  return { publicClient, walletClient };
}

/** account_number and sequence over REST. */
export async function accountSequence(address: string): Promise<{ accountNumber: bigint; sequence: bigint }> {
  const res = await fetch(`${NET.rest}/cosmos/auth/v1beta1/accounts/${address}`);
  if (res.status === 404) throw new Error(`${address} does not exist on chain yet: fund it first`);
  if (!res.ok) throw new Error(`account query failed: HTTP ${res.status}`);
  const body = (await res.json()) as { account?: Record<string, unknown> };
  const a = (body.account?.base_account ?? body.account ?? {}) as Record<string, string>;
  return { accountNumber: BigInt(a.account_number ?? "0"), sequence: BigInt(a.sequence ?? "0") };
}

/** Native-lane fee: hybrid transactions are large, so the gas limit is generous. */
export const NATIVE_FEE = { amount: [{ denom: "uqor", amount: "100000" }], gas: "800000" };

type Messages = Parameters<EthNativeSigner["sign"]>[0]["messages"];

export async function broadcastNative(acc: UnifiedAccount, mode: "hybrid" | "classical", messages: Messages): Promise<string> {
  const { accountNumber, sequence } = await accountSequence(acc.cosmos);
  const signer = new EthNativeSigner(acc, { signMode: mode, rest: NET.rest });
  const transport = await StargateClient.connect(NET.rpc);
  try {
    const res = await signer.signAndBroadcast(transport, { chainId: NET.chainId, accountNumber, sequence, fee: NATIVE_FEE, messages });
    if (res.code !== 0) throw new Error(`native tx ${res.transactionHash} failed with code ${res.code}: ${res.rawLog ?? ""}`);
    return res.transactionHash;
  } finally {
    transport.disconnect();
  }
}

/** A hybrid-signed bank send from the account to itself: the Drill-day "normal transaction". */
export async function hybridSelfTransfer(acc: UnifiedAccount, uqor: bigint): Promise<string> {
  const { accountNumber, sequence } = await accountSequence(acc.cosmos);
  const signer = new EthNativeSigner(acc, { signMode: "hybrid", rest: NET.rest });
  const transport = await StargateClient.connect(NET.rpc);
  try {
    const res = await signer.bankSend(transport, acc.cosmos, [{ denom: "uqor", amount: uqor.toString() }], {
      chainId: NET.chainId,
      accountNumber,
      sequence,
      fee: NATIVE_FEE,
    });
    if (res.code !== 0) throw new Error(`bank send ${res.transactionHash} failed with code ${res.code}`);
    return res.transactionHash;
  } finally {
    transport.disconnect();
  }
}
