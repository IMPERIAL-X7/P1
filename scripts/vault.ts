/**
 * Q-Day Vault CLI for the QoreChain testnet.  Usage: npm run vault -- <command> [args]
 *
 * Setup (once):
 *   init                      create a throwaway drill account (.env) and a guardian key (secrets/)
 *   status                    account, PQC key, EVM window, vault state
 *   register                  register the account's ML-DSA-87 key WITH proof of possession
 *   window-open deploy        open an unscoped window sized for one deployment
 *   deploy [limitQOR] [delaySeconds]   deploy QDayVault (owner key = this account's registered key)
 *   window-open vault         open a window scoped to the vault only (allowed_targets = [vault])
 *   window-close              close the window at once
 *
 * Vault (needs a live vault-scoped window, since this account submits the transactions):
 *   deposit <QOR>
 *   withdraw <to 0x...> <QOR>
 *   execute <id>
 *   cancel <id> [--guardian]
 *   freeze [--guardian]
 *   unfreeze
 *
 * Drill:
 *   drill-tx                  hybrid-signed self-transfer of 1 uqor (no window needed); prints the hash
 *   drill-info                what to paste into the drill registration form
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { buildRegisterPqcKeyMsg, closeEvmWindowMsg, fetchPqcStatus, generatePqcKeypair, generatePqcRecoveryCode, isRegisteredPqcKey, openEvmWindowMsg, signProofOfPossession } from "@qorechain/sdk";
import { evmWindowCost, evmWindowStatus } from "@qorechain/evm";
import { formatEther, getAddress, parseEther, type Address } from "viem";
import { generatePrivateKey } from "viem/accounts";

import { broadcastNative, clients, DEPLOYMENT_FILE, GUARDIAN_FILE, hybridSelfTransfer, loadAccount, loadDeployment, loadGuardian, NET } from "./lib/chain.js";
import * as ops from "./lib/ops.js";
import { Role, toHexBytes } from "./lib/vault.js";

/** Fee cap for our EVM transactions; windows are sized for it. Base fee is ~100 gwei. */
const MAX_FEE = 250_000_000_000n;
const TIP = 1_000_000_000n;
const flag = (f: string) => process.argv.includes(f);
const arg = (i: number) => process.argv.filter((a) => !a.startsWith("--"))[i + 3];

async function init() {
  if (existsSync(".env")) throw new Error(".env already exists: refusing to overwrite an account");
  const env = [
    "# Q-Day Drill account (testnet only, throwaway: its PRIVATE_KEY is handed to the drill bot).",
    "# The ML-DSA-87 key comes ONLY from the recovery code, so the leaked PRIVATE_KEY reveals nothing about it.",
    `PRIVATE_KEY=${generatePrivateKey()}`,
    `QORE_PQC_RECOVERY_CODE=${generatePqcRecoveryCode()}`,
    "QORE_NETWORK=testnet",
    "",
  ].join("\n");
  writeFileSync(".env", env, { mode: 0o600 });
  if (!existsSync(GUARDIAN_FILE)) {
    mkdirSync("secrets", { recursive: true });
    const g = generatePqcKeypair();
    writeFileSync(GUARDIAN_FILE, JSON.stringify({ publicKey: Buffer.from(g.publicKey).toString("hex"), secretKey: Buffer.from(g.secretKey).toString("hex") }), { mode: 0o600 });
  }
  process.loadEnvFile(".env");
  const acc = loadAccount();
  console.log(`drill account: ${acc.cosmos}\n               ${acc.evm}`);
  console.log(`guardian key:  ${GUARDIAN_FILE}`);
  console.log("Back up .env and secrets/ privately. Next: fund the qor1... address, then `npm run vault -- register`.");
}

async function statusCmd() {
  const acc = loadAccount();
  const { publicClient } = clients(acc);
  console.log(`account  ${acc.cosmos}  ${acc.evm}`);
  console.log(`balance  ${formatEther(await publicClient.getBalance({ address: acc.evm as Address }))} QOR`);
  const pqc = await fetchPqcStatus({ rest: NET.rest, address: acc.cosmos });
  const mine = pqc.registered ? isRegisteredPqcKey(pqc, acc.pqc.publicKey) : false;
  console.log(`PQC key  ${pqc.registered ? (mine ? "registered (this key)" : "registered, but NOT this key") : "not registered"}`);
  const w = await evmWindowStatus({ rest: NET.rest, address: acc.cosmos });
  console.log(`window   ${w.found ? `${w.live ? "LIVE" : "not usable"}: ${w.remainingBlocks} blocks, ${w.remainingTxs} txs, ${w.remainingValue} uqor left` : "none"}`);
  if (!existsSync(DEPLOYMENT_FILE)) return console.log("vault    not deployed");
  const s = await ops.status({ publicClient, walletClient: null as never, vault: loadDeployment().vault });
  console.log(`vault    ${loadDeployment().vault}`);
  console.log(`         balance ${formatEther(s.balance)} QOR, frozen ${s.frozen}, delay ${s.delay}s, limit ${formatEther(s.nativeLimit)} QOR/day (${formatEther(s.remainingToday)} left)`);
  console.log(`         nonces owner ${s.nonces.owner} guardian ${s.nonces.guardian} joint ${s.nonces.joint}`);
  for (const it of s.items) {
    const st = ["", "QUEUED", "executed", "cancelled"][it.status];
    console.log(`         #${it.id} kind ${it.kind} ${st} eta ${new Date(Number(it.eta) * 1000).toISOString()} to ${it.to} amount ${it.amount}`);
  }
}

async function register() {
  const acc = loadAccount();
  const pqc = await fetchPqcStatus({ rest: NET.rest, address: acc.cosmos });
  if (pqc.registered) return console.log("already registered");
  const proofOfPossession = signProofOfPossession({ chainId: NET.chainId, account: acc.cosmos, keypair: acc.pqc });
  const msg = buildRegisterPqcKeyMsg(acc.cosmos, { pqcKeypair: acc.pqc, proofOfPossession });
  console.log(`registered (with proof of possession): ${await broadcastNative(acc, "classical", [msg])}`);
}

async function windowOpen() {
  const acc = loadAccount();
  const kind = arg(0);
  let msg;
  if (kind === "deploy") {
    const perTx = evmWindowCost({ gas: 6_000_000n, maxFeePerGas: MAX_FEE });
    msg = openEvmWindowMsg({ sender: acc.cosmos, blocks: 600n, maxTxs: 2n, maxValue: perTx * 2n });
  } else if (kind === "vault") {
    const vault = loadDeployment().vault;
    const deposit = parseEther(arg(1) ?? "0"); // optional: room for a deposit of this many QOR
    const perTx = evmWindowCost({ gas: 1_500_000n, maxFeePerGas: MAX_FEE });
    const maxValue = perTx * 6n + deposit / 1_000_000_000_000n; // wei -> uqor
    msg = openEvmWindowMsg({ sender: acc.cosmos, blocks: 600n, maxTxs: 6n, maxValue, allowedTargets: [vault] });
  } else {
    throw new Error("usage: window-open deploy | window-open vault [depositQOR]");
  }
  console.log(`window opened: ${await broadcastNative(acc, "hybrid", [msg])}`);
  console.log("Wait ~10 s before the next EVM transaction (the nonce advanced).");
}

async function windowClose() {
  const acc = loadAccount();
  console.log(`window closed: ${await broadcastNative(acc, "hybrid", [closeEvmWindowMsg(acc.cosmos)])}`);
}

async function deploy() {
  const acc = loadAccount();
  const guardian = loadGuardian();
  const { publicClient, walletClient } = clients(acc);
  const limit = parseEther(arg(0) ?? "1");
  const delay = BigInt(arg(1) ?? "3600");
  const args = [toHexBytes(acc.pqc.publicKey), toHexBytes(guardian.publicKey), getAddress(acc.evm), limit, delay] as const;
  const hash = await walletClient.deployContract({
    abi: ops.VAULT_ABI,
    bytecode: ops.VAULT_BYTECODE,
    args,
    chain: walletClient.chain,
    account: walletClient.account,
    maxFeePerGas: MAX_FEE,
    maxPriorityFeePerGas: TIP,
    gas: 6_000_000n,
  });
  const r = await publicClient.waitForTransactionReceipt({ hash });
  if (r.status !== "success" || !r.contractAddress) throw new Error(`deploy failed: ${hash}`);
  mkdirSync("deployments", { recursive: true });
  writeFileSync(DEPLOYMENT_FILE, JSON.stringify({ vault: r.contractAddress, deployer: acc.evm, deployerNative: acc.cosmos, txHash: hash, block: Number(r.blockNumber), nativeLimit: limit.toString(), delay: Number(delay) }, null, 2) + "\n");
  console.log(`vault deployed: ${r.contractAddress}\ntx: ${NET.explorer}/tx/${hash}  (gas used ${r.gasUsed})`);
}

function ctx() {
  const acc = loadAccount();
  const { publicClient, walletClient } = clients(acc);
  return { acc, c: { publicClient, walletClient, vault: loadDeployment().vault, tx: { gas: 1_500_000n, maxFeePerGas: MAX_FEE, maxPriorityFeePerGas: TIP } } as ops.Ctx };
}

async function deposit() {
  const { c } = ctx();
  const value = parseEther(arg(0) ?? "");
  const hash = await c.walletClient.sendTransaction({ account: c.walletClient.account!, chain: c.walletClient.chain, to: c.vault, value, gas: 100_000n, maxFeePerGas: MAX_FEE, maxPriorityFeePerGas: TIP });
  await c.publicClient.waitForTransactionReceipt({ hash });
  console.log(`deposited ${formatEther(value)} QOR: ${hash}`);
}

async function main() {
  try {
    process.loadEnvFile(".env");
  } catch {
    // no .env yet (init creates it)
  }
  const cmd = process.argv[2];
  const role = flag("--guardian") ? Role.GUARDIAN : Role.OWNER;
  const signer = () => (role === Role.GUARDIAN ? loadGuardian() : loadAccount().pqc);
  switch (cmd) {
    case "init": return init();
    case "status": return statusCmd();
    case "register": return register();
    case "window-open": return windowOpen();
    case "window-close": return windowClose();
    case "deploy": return deploy();
    case "deposit": return deposit();
    case "withdraw": {
      const { acc, c } = ctx();
      return console.log(`withdraw: ${await ops.withdraw(c, acc.pqc, getAddress(arg(0)!), parseEther(arg(1)!))}`);
    }
    case "execute": return console.log(`execute: ${await ops.execute(ctx().c, BigInt(arg(0)!))}`);
    case "cancel": return console.log(`cancel: ${await ops.cancel(ctx().c, signer(), role, BigInt(arg(0)!))}`);
    case "freeze": return console.log(`freeze: ${await ops.freeze(ctx().c, signer(), role)}`);
    case "unfreeze": {
      const { acc, c } = ctx();
      return console.log(`unfreeze: ${await ops.unfreeze(c, acc.pqc, loadGuardian())}`);
    }
    case "drill-tx": {
      const hash = await hybridSelfTransfer(loadAccount(), 1n);
      return console.log(`drill tx (hybrid-signed self-transfer): ${hash}\n${NET.explorer}/tx/${hash}\nSubmit this hash on the project page.`);
    }
    case "drill-info": {
      const acc = loadAccount();
      const d = existsSync(DEPLOYMENT_FILE) ? loadDeployment().vault : "(not deployed yet)";
      return console.log(`Drill registration:\n  account:            ${acc.cosmos}  (${acc.evm})\n  ECDSA private key:  ${process.env.PRIVATE_KEY}\n  contract to attack: ${d}\nBefore 18 Nov 00:00 UTC: run window-close and check status shows "window none".`);
    }
    default:
      console.log(readFileSync(new URL(import.meta.url), "utf8").split("*/")[0]);
      process.exitCode = cmd ? 1 : 0;
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
