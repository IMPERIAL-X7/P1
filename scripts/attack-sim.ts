/**
 * attack-sim.ts - play the Q-Day Drill attacker against our own account and vault, live on
 * testnet. It knows ONLY the account's ECDSA private key (PRIVATE_KEY), exactly what the drill
 * bot gets. It never reads the PQC recovery code or the guardian key; where a post-quantum key
 * is needed it uses its own guess.
 *
 *   npm run attack
 *
 * Every attack must end BLOCKED. The script exits non-zero if any attack succeeds.
 * Native-lane attacks are real broadcasts (the chain refuses them, so they cost nothing);
 * contract-layer attacks are eth_call simulations, i.e. "what if a window were open".
 */
import { StargateClient } from "@cosmjs/stargate";
import {
  EthNativeSigner,
  buildRegisterPqcKeyMsg,
  generatePqcKeypair,
  generatePqcRecoveryCode,
  openEvmWindowMsg,
  signProofOfPossession,
  unifiedAccountFromSeed,
} from "@qorechain/sdk";
import { createPublicClient, createWalletClient, getAddress, http, keccak256, parseEther, type Address, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { accountSequence, loadDeployment, NATIVE_FEE, NET, qoreTestnet } from "./lib/chain.js";
import { VAULT_ABI } from "./lib/ops.js";
import { Action, buildMessage, NATIVE, Role, signMessage, toHexBytes } from "./lib/vault.js";

process.loadEnvFile(".env");
const stolenKey = process.env.PRIVATE_KEY as Hex; // the ONLY secret the attacker has

// The attacker's view of the account: the real ECDSA key, and a post-quantum key it made up.
const victim = unifiedAccountFromSeed(Buffer.from(stolenKey.slice(2), "hex"), { recoveryCode: generatePqcRecoveryCode() });
const thief = getAddress(privateKeyToAccount(generatePrivateKey()).address); // where the loot would go
const thiefCosmos = unifiedAccountFromSeed(Buffer.from(generatePrivateKey().slice(2), "hex"), { recoveryCode: generatePqcRecoveryCode() }).cosmos;
const attackerPq = generatePqcKeypair();
const vault = loadDeployment().vault;
const transport = http(NET.evm);
const publicClient = createPublicClient({ chain: qoreTestnet, transport });
const wallet = createWalletClient({ chain: qoreTestnet, transport, account: privateKeyToAccount(stolenKey) });

let breaches = 0;
async function attack(name: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    const r = await fn();
    breaches++;
    console.log(`!! SUCCEEDED  ${name}  ${String(r)}`);
  } catch (e) {
    const msg = reason(e).replace(/\s+/g, " ");
    console.log(`   BLOCKED    ${name}\n              ${msg.slice(0, 160)}`);
  }
}

/** The most specific cause: a decoded custom error name, the node's own message, or the error text. */
function reason(e: unknown): string {
  let cur = e as { cause?: unknown; data?: { errorName?: string }; details?: string; shortMessage?: string; message?: string } | undefined;
  let details = "";
  while (cur) {
    if (cur.data?.errorName) return `reverted with ${cur.data.errorName}()`;
    if (cur.details) details = cur.details;
    cur = cur.cause as typeof cur;
  }
  if (details) return `node said: ${details}`;
  return e instanceof Error ? ((e as { shortMessage?: string }).shortMessage ?? e.message) : String(e);
}

async function native(mode: "classical" | "hybrid", messages: Parameters<EthNativeSigner["sign"]>[0]["messages"]) {
  const { accountNumber, sequence } = await accountSequence(victim.cosmos);
  const signer = new EthNativeSigner(victim, { signMode: mode, rest: NET.rest });
  const tm = await StargateClient.connect(NET.rpc);
  try {
    const res = await signer.signAndBroadcast(tm, { chainId: NET.chainId, accountNumber, sequence, fee: NATIVE_FEE, messages });
    if (res.code !== 0) throw new Error(`refused by the chain: code ${res.code} ${res.rawLog ?? ""}`);
    return res.transactionHash;
  } finally {
    tm.disconnect();
  }
}

const sendAll = { typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: { fromAddress: victim.cosmos, toAddress: thiefCosmos, amount: [{ denom: "uqor", amount: "1000000" }] } };

async function simulate(functionName: string, args: unknown[]) {
  await publicClient.simulateContract({ address: vault, abi: VAULT_ABI, functionName, args, account: getAddress(victim.evm) });
  return "simulation passed";
}

async function main() {
  console.log(`Attacker holds the ECDSA key of ${victim.cosmos} (${victim.evm}) and nothing else.`);
  console.log(`Vault under attack: ${vault}\n`);

  console.log("Native lane (real broadcasts):");
  await attack("bank send, ECDSA-only signature", () => native("classical", [sendAll]));
  await attack("bank send, hybrid with a guessed post-quantum key", () => native("hybrid", [sendAll]));
  await attack("open an EVM window, ECDSA-only", () => native("classical", [openEvmWindowMsg({ sender: victim.cosmos, blocks: 100n, maxTxs: 10n, maxValue: 1_000_000_000n })]));
  await attack("open an EVM window, hybrid with a guessed key", () => native("hybrid", [openEvmWindowMsg({ sender: victim.cosmos, blocks: 100n, maxTxs: 10n, maxValue: 1_000_000_000n })]));
  const pop = signProofOfPossession({ chainId: NET.chainId, account: victim.cosmos, keypair: attackerPq });
  await attack("replace the account's PQC key with the attacker's (classical)", () =>
    native("classical", [buildRegisterPqcKeyMsg(victim.cosmos, { pqcKeypair: attackerPq, proofOfPossession: pop })]));

  console.log("\nEVM lane (real transactions, no window is open):");
  await attack("plain QOR transfer to the thief", () => wallet.sendTransaction({ to: thief, value: parseEther("1"), gas: 21_000n }));
  await attack("vault.withdraw with a junk signature", () =>
    wallet.writeContract({ address: vault, abi: VAULT_ABI, functionName: "withdraw", args: [NATIVE, thief, parseEther("1"), 9_999_999_999n, toHexBytes(attackerPq.publicKey), `0x${"00".repeat(4627)}`], gas: 1_500_000n }));

  console.log("\nContract layer (eth_call: what if a window WERE open?):");
  const chainId = BigInt(await publicClient.getChainId());
  const block = await publicClient.getBlock();
  const deadline = block.timestamp + 600n;
  const nonce = (await publicClient.readContract({ address: vault, abi: VAULT_ABI, functionName: "nonces", args: [Role.OWNER] })) as bigint;
  const ownerPk = await ownerPublicKey();
  const m = buildMessage({ chainId, vault, role: Role.OWNER, nonce, deadline, action: Action.WITHDRAW, to: thief, amount: parseEther("1") });
  const attackerSig = signMessage(attackerPq, m);
  await attack("withdraw signed with the attacker's own ML-DSA key", () => simulate("withdraw", [NATIVE, thief, parseEther("1"), deadline, toHexBytes(attackerPq.publicKey), attackerSig]));
  await attack("withdraw: owner's public key + attacker's signature", () => simulate("withdraw", [NATIVE, thief, parseEther("1"), deadline, ownerPk, attackerSig]));
  await attack("withdraw: owner's public key + random bytes", () => simulate("withdraw", [NATIVE, thief, parseEther("1"), deadline, ownerPk, `0x${"ab".repeat(4627)}`]));
  await attack("take over: propose the attacker's key as owner", () => {
    const mm = buildMessage({ chainId, vault, role: Role.OWNER, nonce, deadline, action: Action.SET_OWNER_KEY, value: keccak256(toHexBytes(attackerPq.publicKey)) });
    return simulate("proposeOwnerKey", [toHexBytes(attackerPq.publicKey), Role.OWNER, deadline, ownerPk, signMessage(attackerPq, mm)]);
  });
  await attack("raise the daily limit to everything", () => simulate("proposeLimit", [NATIVE, parseEther("1000"), deadline, ownerPk, attackerSig]));
  await attack("freeze the vault (griefing)", () => simulate("freeze", [Role.OWNER, deadline, ownerPk, attackerSig]));
  await attack("replay a real past owner signature from the chain", () => replayPast(ownerPk));

  const bal = await publicClient.getBalance({ address: vault });
  console.log(`\nVault balance after the attack: ${Number(bal) / 1e18} QOR`);
  console.log(breaches === 0 ? "RESULT: every attack was blocked." : `RESULT: ${breaches} attack(s) SUCCEEDED.`);
  if (breaches) process.exitCode = 1;
}

/** The owner's public key is public: read it from the calldata of a past vault transaction. */
async function ownerPublicKey(): Promise<Hex> {
  const tx = await lastVaultCall("withdraw");
  return tx.args[4] as Hex;
}

async function lastVaultCall(fn: string) {
  const { decodeFunctionData } = await import("viem");
  const latest = await publicClient.getBlockNumber();
  const dep = loadDeployment() as { vault: Address; block?: number };
  for (let b = latest; b >= BigInt(dep.block ?? 0) && b > latest - 3000n; b--) {
    const blk = await publicClient.getBlock({ blockNumber: b, includeTransactions: true });
    for (const tx of blk.transactions.slice().reverse()) {
      if (typeof tx === "string" || tx.to?.toLowerCase() !== vault.toLowerCase()) continue;
      try {
        const d = decodeFunctionData({ abi: VAULT_ABI, data: tx.input });
        if (d.functionName === fn) return { args: d.args as readonly unknown[] };
      } catch {
        // not a vault call we can decode
      }
    }
  }
  throw new Error(`no past ${fn} transaction found`);
}

async function replayPast(ownerPk: Hex) {
  const past = await lastVaultCall("withdraw");
  const [asset, , amount, deadline, , sig] = past.args as [Address, Address, bigint, bigint, Hex, Hex];
  // Unchanged replay (would pay the owner's chosen recipient again) and redirected replay.
  await simulate("withdraw", [asset, thief, amount, deadline, ownerPk, sig]).catch(() => undefined);
  return simulate("withdraw", past.args as unknown[]);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exitCode = 1;
});
