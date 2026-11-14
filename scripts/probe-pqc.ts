/**
 * probe-pqc.ts - check, against the live testnet precompile, exactly which bytes
 * `pqcVerify` (0x...0A01) verifies. Read-only: it uses eth_call, so it needs no
 * account, no funds and no EVM window.
 *
 *   npm run probe
 *
 * It signs fresh throwaway keys with the SDK and asks the chain to verify:
 *   1. raw message bytes                       -> expect true
 *   2. the same signature, one message bit flipped  -> expect false
 *   3. a signature by another key              -> expect false
 *   4. a vault-shaped message (0xFF tag + abi.encode)   -> expect true
 */
import { createPublicClient, encodeAbiParameters, http, keccak256, toHex, type Hex } from "viem";
import { generatePqcKeypair, pqcSign } from "@qorechain/sdk";

const RPC = process.env.QORE_EVM_RPC ?? "https://evm-testnet.qore.host";
const PQC_VERIFY = "0x0000000000000000000000000000000000000a01" as const;
const PQC_STATUS = "0x0000000000000000000000000000000000000a02" as const;

const abi = [
  {
    type: "function",
    name: "pqcVerify",
    stateMutability: "view",
    inputs: [
      { name: "pubkey", type: "bytes" },
      { name: "signature", type: "bytes" },
      { name: "message", type: "bytes" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
  },
  {
    type: "function",
    name: "pqcKeyStatus",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [
      { name: "registered", type: "bool" },
      { name: "algorithmId", type: "uint8" },
      { name: "pubkey", type: "bytes" },
      { name: "possessionProven", type: "bool" },
    ],
  },
] as const;

const client = createPublicClient({ transport: http(RPC) });

async function verify(pk: Uint8Array, sig: Uint8Array, msg: Uint8Array): Promise<boolean> {
  return client.readContract({
    address: PQC_VERIFY,
    abi,
    functionName: "pqcVerify",
    args: [toHex(pk), toHex(sig), toHex(msg)],
  });
}

function check(name: string, got: boolean, want: boolean): boolean {
  console.log(`${got === want ? "PASS" : "FAIL"}  ${name}: got ${got}, expected ${want}`);
  return got === want;
}

async function main(): Promise<void> {
  console.log(`chain id: ${await client.getChainId()}  (${RPC})`);
  const a = generatePqcKeypair();
  const b = generatePqcKeypair();
  const msg = new TextEncoder().encode("Q-Day Vault probe");
  const sig = pqcSign(a.secretKey, msg);
  console.log(`pk ${a.publicKey.length} bytes, sig ${sig.length} bytes`);

  let ok = true;
  ok = check("raw bytes, right key", await verify(a.publicKey, sig, msg), true) && ok;
  const flipped = msg.slice();
  flipped[0] ^= 1;
  ok = check("one bit of the message flipped", await verify(a.publicKey, sig, flipped), false) && ok;
  ok = check("signature checked against another key", await verify(b.publicKey, sig, msg), false) && ok;
  ok = check("hedged signature", await verify(a.publicKey, pqcSign(a.secretKey, msg, { hedged: true }), msg), true) && ok;

  // A vault-shaped message: first ABI word is the 0xFF-prefixed domain tag.
  const tag = ("0xff" + Buffer.from("QDAY-VAULT-v1").toString("hex")).padEnd(66, "0") as Hex;
  const vaultMsg = encodeAbiParameters(
    [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "uint8" }, { type: "uint256" }, { type: "uint64" }],
    [tag, 9800n, "0x000000000000000000000000000000000000dEaD", 1, 0n, 2_000_000_000n],
  );
  const vaultBytes = Buffer.from(vaultMsg.slice(2), "hex");
  ok = check("vault-shaped message", await verify(a.publicKey, pqcSign(a.secretKey, vaultBytes), vaultBytes), true) && ok;
  ok = check("keccak digest of it does NOT verify the raw-message signature", await verify(a.publicKey, pqcSign(a.secretKey, vaultBytes), Buffer.from(keccak256(vaultMsg).slice(2), "hex")), false) && ok;

  // Gas estimate for a verify call.
  const data = (await import("viem")).encodeFunctionData({
    abi,
    functionName: "pqcVerify",
    args: [toHex(a.publicKey), toHex(sig), toHex(msg)],
  });
  const gas = await client.estimateGas({ to: PQC_VERIFY, data });
  console.log(`estimateGas for one pqcVerify call: ${gas}  (calldata ${(data.length - 2) / 2} bytes)`);

  const st = await client.readContract({
    address: PQC_STATUS,
    abi,
    functionName: "pqcKeyStatus",
    args: ["0x0000000000000000000000000000000000000001"],
  });
  console.log(`pqcKeyStatus(0x..01): ${JSON.stringify(st)}`);

  console.log(ok ? "\nAll checks passed." : "\nSOME CHECKS FAILED.");
  if (!ok) process.exitCode = 1;
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
