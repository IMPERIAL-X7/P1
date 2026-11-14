# Q-Day Vault: design and security proofs

> **In one sentence:** funds and settings in this vault change only when a **post-quantum (ML-DSA-87) signature** says so. The vault never looks at who sent the transaction, so a stolen ECDSA key, or one broken by a quantum computer, moves nothing.

This document states exactly what we claim, under which assumptions, and proves each claim from the code in [`contracts/QDayVault.sol`](../contracts/QDayVault.sol). Every claim has tests in [`test/QDayVault.ts`](../test/QDayVault.ts) (mapping in §9).

**Reading guide.** §1 is the summary. §2 lists the features. §3 states the model and assumptions. §4–5 define the messages and the state machine precisely. §6 has the proofs, each one short. §7 covers the Q-Day Drill account. §8 says what we do **not** claim.

---

## 1. What we claim

| # | Claim | Attacker | Holds if |
|---|---|---|---|
| **T1** | A classical key alone moves **nothing**. Every outflow goes to a recipient, in an amount, that the owner signed with ML-DSA-87. | Knows **every** ECDSA key, can send any transaction, sees every past signature. | ML-DSA-87 is unforgeable |
| **T2** | Each signature authorises **one** action, **once**, on **this** vault on **this** chain, before its deadline. | Same | Same |
| **L3** | Signatures can't be carried between the vault and QoreChain's own signing formats, in either direction. | Same | Byte-level fact (proved) |
| **T4** | Instant outflow is capped per asset per UTC day. Everything bigger, and every settings change, waits publicly for a delay `D`. | Anyone | Code |
| **T5** | **One** stolen post-quantum key is still not enough. A stolen guardian key loses 0. A stolen owner key loses at most ≈ 2 days' instant limit before the guardian freezes it. | Holds one of the two PQ keys | Honest side checks at least once per `D` |
| **L6** | When a key is replaced (recovery, rotation, guardian swap), nothing it queued can ever execute. | | Code |
| **L7** | The vault **fails closed**. If the precompile is missing, broken or says anything but "valid", nothing happens. | | Code |
| **T8** | Liveness: with no attacker, the owner can always get all funds out, and one lost key can always be replaced using the other. | | Precompile active |

---

## 2. Features

**Built (this contract):**

1. **PQ-only authorisation.** Every value-moving or settings-changing call checks an ML-DSA-87 signature through QoreChain's `pqcVerify` precompile (`0x…0A01`). `msg.sender` is never used for authorisation.
2. **Relayer-friendly.** Because the signature is the authority, **anyone** can submit a signed action. The user never needs an EVM window for vault actions; a relayer with a *scoped* window (`allowed_targets = [vault]`) can submit them.
3. **On-chain key binding.** At deployment, the owner key can be required to be the account's registered QoreChain key. This is checked through `pqcKeyStatus` (`0x…0A02`): `registered`, `algorithmId == 1`, `possessionProven`, and an identical public key.
4. **Two keys: owner + guardian.** The guardian is optional and is a separate ML-DSA-87 key, e.g. kept offline. Each role has its **own nonce**, so neither can invalidate the other's pre-signed messages.
5. **Daily instant limit, per asset.** Small withdrawals execute at once. Anything above the day's remaining allowance is **queued** for delay `D`. Tokens default to limit 0, so every token withdrawal is queued.
6. **Time-locked settings.** Changes to limits, delay, guardian key and owner key are all queued for `D`.
7. **Cancel.** Owner *or* guardian can cancel any queued item.
8. **Freeze / unfreeze.** Owner *or* guardian can freeze, which stops every withdrawal. Unfreezing needs **both** to sign the same message.
9. **Recovery.** The guardian can propose a new owner key, which takes effect after `D` unless the owner cancels it. Every queued item remembers the key that authorised it, and it **dies** if that key is replaced. So after a recovery, nothing the thief queued can run. The same holds after replacing a stolen guardian key.
10. **Pre-signed panic button.** Thanks to per-role nonces, the guardian can sign a `FREEZE` in advance and hand it to a watcher bot. If it leaks, the worst anyone can do with it is freeze the vault.
11. **Native QOR and ERC-20 tokens.**
12. **Fail-closed checks.** Precompile answers must be exactly an ABI `true`. Public keys must be 2,592 bytes and not "degenerate" (a key whose `t1` part is all zero, for which anyone can forge signatures).

**Planned:** a web UI that signs in the browser and shows decoded messages; a relayer; a watchtower that alerts on `Queued` events and holds the pre-signed freeze; a live "Q-Day attack simulator" page; the two-stage QCAI audit reports.

---

## 3. Model

### 3.1 Parties and keys

| Party | Secret | Can do in the vault |
|---|---|---|
| **Owner** | ML-DSA-87 secret key $sk_O$ | withdraw, propose any setting, cancel, freeze, co-sign unfreeze |
| **Guardian** (optional) | ML-DSA-87 secret key $sk_G$ | cancel, freeze, propose a new owner key, co-sign unfreeze |
| **Anyone** | nothing | deposit; submit signed actions; execute queued items once their delay has passed |

The vault stores only hashes: $h_O = \mathrm{keccak256}(pk_O)$ and $h_G = \mathrm{keccak256}(pk_G)$, with $h_G = 0$ meaning "no guardian". Each signed call carries the full public key (2,592 bytes) and signature (4,627 bytes) as calldata.

### 3.2 Attackers

* **A0, "Q-Day" (the Drill):** knows **every ECDSA private key**, including the owner's QoreChain account key, the deployer's and every relayer's. Can send any transaction with any calldata, front-run, and read every signature ever published. Does **not** know $sk_O$ or $sk_G$.
* **A_O:** A0 plus the owner's ML-DSA key $sk_O$.
* **A_G:** A0 plus the guardian's ML-DSA key $sk_G$.
* **A_OG:** both PQ keys. Nothing can protect against this (see §8).

### 3.3 Assumptions

* **H1. ML-DSA-87 is unforgeable** (EUF-CMA, NIST FIPS 204, security category 5). Without $sk$, no efficient classical *or quantum* adversary can produce a valid signature on a message the key holder never signed. We do **not** need signatures to be unique: replay protection uses nonces, not signature bytes.
* **H2. keccak256 is second-preimage resistant.** Given $pk$, nobody can find a different $pk'$ with the same hash. That costs ~$2^{256}$ classically and ~$2^{128}$ with Grover's algorithm.
* **H3. The precompile is correct:** `pqcVerify(pk, sig, m)` returns `true` exactly when `sig` is a valid FIPS-204 ML-DSA-87 signature on the raw bytes `m`. We checked this on testnet on 14 Nov 2026 with [`scripts/probe-pqc.ts`](../scripts/probe-pqc.ts):
  * a correct signature → `true`;
  * one flipped bit → `false`;
  * another key → `false`;
  * a hedged signature → `true`;
  * a vault-shaped message → `true`;
  * its hash instead of the message → `false`.
* **H4. The chain runs the contract as written.** Transactions are atomic: a revert undoes everything. `block.timestamp` never decreases and stays within seconds of real time.
* **H5. Honest key holders sign only what they mean to.** Their secret keys stay secret unless the attacker class says otherwise.
* **H6. Monitoring (only for T5):** the honest side looks at the vault at least once every `D` seconds and reacts.

---

## 4. Signed messages

### 4.1 Format

Every signature is over a message $M$ of **12 ABI words, always exactly 384 bytes** (`_message`, and independently `buildMessage` in [`scripts/lib/vault.ts`](../scripts/lib/vault.ts); the tests check that the two are byte-identical):

| Word | Field | Meaning |
|---|---|---|
| 0 | `DOMAIN_TAG` | `0xFF ‖ "QDAY-VAULT-v1" ‖ 0…0` |
| 1 | `chainid` | the chain (9800 on testnet) |
| 2 | `vault` | this vault's address |
| 3 | `role` | 1 owner, 2 guardian, 3 joint |
| 4 | `nonce` | the role's next nonce |
| 5 | `deadline` | last valid second |
| 6 | `action` | 1 withdraw … 8 unfreeze |
| 7 | `asset` | token, or 0 for QOR |
| 8 | `to` | recipient |
| 9 | `amount` | amount / new limit / new delay |
| 10 | `id` | queued item (for cancel) |
| 11 | `value` | new key hash (for key changes) |

Fields an action doesn't use are 0. The contract fills every word from the call's own parameters or from its own state (`chainid`, `address(this)`, `nonces[role]`). The caller never supplies the message.

**Lemma 1 (one message, one meaning).** Two different field tuples never give the same $M$.
*Proof.* Every field is a static ABI type. `abi.encode` writes field $i$, left-padded to 32 bytes, at bytes $[32i, 32i+32)$. Reading word $i$ back gives field $i$, so the encoding has an inverse and is injective. ∎

### 4.2 When a signature counts

`_check(h, pk, σ, M)` passes only if all of these hold: $h \ne 0$, $|pk| = 2592$, $\mathrm{keccak256}(pk) = h$, $|σ| = 4627$, and the precompile returns exactly the ABI word `1`.

**Lemma 2 (a passing check means the key holder signed).** If `_check(h_r, pk, σ, M)` passes, the holder of role $r$'s secret key signed $M$.
*Proof.* By H3, the precompile returned `true`, so σ is a valid signature on $M$ under $pk$. By H2, $\mathrm{keccak256}(pk) = h_r$ forces $pk = pk_r$. By H1, only the holder of $sk_r$ can produce a valid signature on $M$ under $pk_r$. ∎

### 4.3 Domain separation

The owner's key may be the same ML-DSA key the account uses for QoreChain transactions (feature 3). Those transaction signatures are **public**, so we must show that no chain signature is ever a vault signature, and no vault signature is ever a chain signature.

**Lemma 3.** No vault message equals any message in any ML-DSA signing format of the QoreChain SDK 0.14.0. These formats were read from the SDK source on 14 Nov 2026.
*Proof.* Every vault message has length 384 and first byte `0xFF`. Take each SDK format in turn:

| SDK format | Shape | Why it can't be a vault message |
|---|---|---|
| Proof of possession `qorechain-pqc-pop-v1\|…`; key rotation `qorechain-pqc-rotate-v1\|…`; migration v1; bridge attestation v1; authenticator link `QoreChain authenticator link v1\n…` | UTF-8 text | The byte `0xFF` never occurs in UTF-8 (RFC 3629) |
| Hybrid tx v2 `qorechain-pqc-hybrid-v2…`; migration v2; bridge attestation v2 | ASCII prefix | First byte is `q` (`0x71`), not `0xFF` |
| EVM auth v1/v2, Cosmos auth | SHA-256 digest | Exactly 32 bytes long, not 384 |
| Hybrid tx v1 `BE32(len B0) ‖ B0 ‖ BE32(len A) ‖ A` | Length-framed | A first byte of `0xFF` means `len B0` ≥ `0xFF000000`, so the message is longer than 4.2 GB, not 384 bytes |

So the sets of messages are disjoint. A signature is bound to its exact bytes (H1), so it never crosses between them. ∎

*Scope.* Lemma 3 covers the formats that exist today. For the strongest separation against future formats, deploy with a **dedicated** owner key (`ownerAccount = 0`), used for nothing but this vault.

---

## 5. State machine

**State:**
* keys: `ownerKeyHash` ($h_O \ne 0$) and `guardianKeyHash` ($h_G$, may be 0);
* `delay` $D \in [5\text{ min}, 30\text{ days}]$;
* `frozen`;
* `nonces[role]`;
* `dailyLimit[asset]`;
* `spent[asset] = (day, amount)`;
* `keyVersion[role]`, which increases on every key replacement;
* a list of queued items, each `(kind, status, signerRole, eta, asset, to, amount, value, signerVersion)`.

| Function | Signature needed | Effect |
|---|---|---|
| `receive` | none | adds QOR |
| `withdraw(asset,to,amount)` | owner | if not frozen: pay now if it fits today's allowance, otherwise queue |
| `proposeLimit` / `proposeDelay` / `proposeGuardianKey` | owner | queue the change |
| `proposeOwnerKey` | owner **or** guardian | queue the change |
| `cancel(id)` | owner **or** guardian | queued item → cancelled |
| `freeze` | owner **or** guardian | `frozen = true` |
| `unfreeze` | owner **and** guardian (or the owner alone if there's no guardian) | `frozen = false` |
| `execute(id)` | none | if queued, `now ≥ eta`, and the signer's `keyVersion` is unchanged: apply it (a withdrawal also needs not frozen) |

Every signed call goes through `_authorize`: check the deadline, then `_check` with the current nonce, then increase that nonce by exactly 1. This all happens **before** any other state change. Every function that changes state is `nonReentrant`.

---

## 6. Theorems and proofs

### Theorem 1: a classical key alone moves nothing

*Against A0, the only changes to the vault are:*
* *(i) deposits;*
* *(ii) executing a queued item after its delay, exactly as it was signed;*
* *(iii) submitting a signature the honest party produced, which does exactly what they signed.*

*So every asset that leaves goes to a recipient, in an amount, that $sk_O$ signed.*

**Proof.** Go through every function that changes state:

* `receive` only adds funds.
* `withdraw`, `propose*`, `cancel` and `freeze` call `_authorize` before any other change. It reverts unless `_check` passes, which by Lemma 2 means the holder of $sk_O$ or $sk_G$ signed this exact message. A0 holds neither key, so by H1 the only signatures available to A0 are ones the honest parties made. By Theorem 2, each of those performs exactly the signed action, once.
* `unfreeze` runs `_check` with the owner's key, and with the guardian's key if one is set. Same argument.
* `execute` needs no signature, but only acts on an item whose status is `QUEUED`. Only `_queue` creates such items, and `_queue` only runs after `_authorize`. The stored fields are the signed fields. The status changes to `EXECUTED` before any effect, so an item runs at most once.

Funds leave only through `_transfer`. It is called from `withdraw`, with the signed `asset`, `to` and `amount`, and from `execute` of a `WITHDRAW` item, with the stored copies of those signed fields. `msg.sender` appears only in the `Deposited` event. ∎

Front-running doesn't help A0. A copied transaction does exactly what the owner signed, and changing any field breaks the signature (Lemma 1).

### Theorem 2: one signature, one action, once

*A valid signature σ on $M$ causes at most one successful call. That call is on the vault and chain named in $M$, before $M$'s deadline, and it is exactly the action and parameters in $M$.*

**Proof.**
* **Meaning.** Each function builds $M$ from exactly the parameters that decide its effect, plus its own action code and the role. By Lemma 1, one $M$ matches one function and one parameter set.
* **Once.** A successful call by role $r$ uses the current `nonces[r]` and increases it by 1. The other two roles' counters are separate and never decrease. So any two successful calls of role $r$ used different nonces, and therefore different messages (Lemma 1). Messages also include `role`, so an owner message is never a guardian message.
* **Place.** $M$ includes `address(this)` and `chainid`, so it fails `_check` on any other vault or chain.
* **Time.** `block.timestamp > deadline` reverts. ∎

*Note:* an honest signer can cancel a signed but unsent message by letting its deadline pass, or by using that nonce for another action.

### Lemma 3 (domain separation)

Proved in §4.3.

### Theorem 4: rate limit and delay

*Let $L_a(d)$ be the largest `dailyLimit[a]` in force during UTC day $d$. Then:*
* *(a) the instant withdrawals of asset $a$ on day $d$ total at most $L_a(d)$;*
* *(b) over any period of $T$ seconds, instant outflow of $a$ is at most $(\lceil T/86400\rceil + 1)\cdot \max_d L_a(d)$;*
* *(c) every other outflow, and every settings change, was announced by a public `Queued` event at least $D$ seconds before it could take effect.*

**Proof.**
* **(a)** An invariant: after each instant withdrawal on day $d$, `spent[a] = (d, S)`, where $S$ is the day's running total, and $S \le$ `dailyLimit[a]` at that moment. The code computes `used` as the day's total (0 on a new day) and pays only if `used + amount ≤ dailyLimit[a]`, so each payment keeps the invariant. The day's final total is therefore at most the largest limit in force that day.
* **(b)** A period of $T$ seconds touches at most $\lceil T/86400\rceil + 1$ UTC days. Add (a) over those days.
* **(c)** Any other outflow is an executed `WITHDRAW` item. `_queue` sets `eta = now + D` and emits `Queued`, and `execute` requires `now ≥ eta`. Settings changes are queued in the same way. A new `D` only applies to items queued *after* it takes effect, because `eta` is fixed when an item is queued. ∎

### Theorem 5: one stolen post-quantum key is not enough

Assume H6.

**(a) A_G (guardian key stolen; owner honest): no funds are lost.**
*Proof.* The guardian key can only sign `cancel`, `freeze`, `proposeOwnerKey`, and its half of `unfreeze`. Limit, delay and guardian-key changes check $h_O$. None of the guardian's actions pays anyone. Its only dangerous action, a new owner key, is queued for $D$. By H6 the owner sees the `Queued` event in time and cancels it. Nothing can stop that cancel: the item can't execute before `eta`, and the owner's nonce is separate. ∎
*(A_G can freeze the vault. That costs availability, not funds; see §8.)*

**(b) A_O (owner key stolen; guardian honest): loss ≤ $(\lceil T/86400\rceil+1)\cdot L$, where $T$ is the time from compromise until the guardian's `freeze` lands. With $D \le 1$ day and a freeze at the first check, $T \le D$, so the loss is at most $2L$.**
*Proof.*
* Instant withdrawals are capped by Theorem 4(b).
* Everything else A_O can do is queued for $D$: big withdrawals, raising the limit, shortening the delay, replacing the guardian, rotating the owner key. By H6 the guardian cancels each one or freezes within $D$.
* After `freeze`, `withdraw` reverts, and `execute` reverts for withdrawals.
* `unfreeze` needs a guardian signature on the joint message (Lemma 2), which A_O can't forge (H1). ∎

The guardian then proposes a new owner key. If A_O cancels it, the vault stays frozen: **funds are stuck, not stolen** (§8).

### Lemma 6: replacing a key kills its queue

*Once the owner (or guardian) key is replaced, no item that the old key authorised can ever execute, even if the same key is later set again.*
**Proof.** Each role has a counter `keyVersion[role]`. It increases by 1 exactly when that role's key is replaced (executing `SET_OWNER_KEY` or `SET_GUARDIAN_KEY`) and never decreases. `_queue` stores the signer's role and the current `keyVersion[role]`, and `execute` requires them to still be equal. After a replacement the counter is strictly larger than the stored value, forever. ∎

*Why per key?* Our first draft bumped one global epoch, and only on owner-key changes. The adversarial review found the gap: after a stolen **guardian** key was replaced, the thief's queued owner-key proposal could still execute. A second draft compared key *hashes*, which would let items come back to life if an old key was ever set again. A counter that only increases has neither problem. Tests: "replacing the guardian kills every item the old guardian queued", "an owner rotation kills the owner's other pending items", "swapping a key away and back does not revive its old items". (An honest owner rotation therefore also cancels the owner's own pending items, which is the safe default.)

### Lemma 7: fail closed

*No failure is ever treated as "valid".*
**Proof.** `_check` requires the call to succeed, the return data to be **exactly 32 bytes**, and its value to be **exactly 1**. Each failure case is refused:
* **An inactive precompile** succeeds but returns empty data (QoreChain docs; this is the case on mainnet today). That is refused.
* **`false`, garbage or a revert** is refused.
* **Keys with the wrong length** are refused.
* **Degenerate keys** are refused at deployment and on every key change (`_wellFormedKey`).
* **The `pqcKeyStatus` binding** requires a non-empty answer with `registered`, `algorithmId == 1`, `possessionProven`, and the same key. ∎

### Theorem 8: liveness

*With the precompile active and no attacker:*
* *(a) the owner can withdraw any amount up to the balance;*
* *(b) a lost guardian key or a lost owner key can be replaced using the other one.*

**Proof.**
* **(a)** If not frozen, `withdraw` either pays at once or queues the amount. Anyone can `execute` it after $D$. If frozen, both keys sign `unfreeze`.
* **(b) Lost guardian key.** The owner proposes a new guardian. This is allowed while frozen, and anyone can execute it after $D$. Then unfreeze jointly with the new guardian.
* **(b) Lost owner key.** The guardian proposes a new owner key, and after $D$ anyone can execute it. ∎

---

## 7. The Q-Day Drill account

In the Drill, the organisers' bot gets the **ECDSA key** of our testnet account. Theorem 1 covers the vault. These chain rules, from the QoreChain docs, cover the account itself:

1. **Native transfers.** Once the account's ML-DSA-87 key is registered, every native transaction needs a **hybrid** signature (ECDSA + ML-DSA). An ECDSA-only transaction is refused (pqc code 20).
2. **EVM transactions.** These need a **live EVM window**. Opening a window is a hybrid-signed native message, so the bot can't open one. **Our procedure:** close every window (`closeEvmWindowMsg`) before the Drill starts. Even if a window were left open, Theorem 1 still protects the vault, because the vault ignores `msg.sender`.
3. **Key independence.** We create the drill account with `unifiedAccountFromSeed(ecdsaKey, { recoveryCode })`. Its ML-DSA key is derived **only** from a separate secret recovery code, so the leaked ECDSA key carries **zero information** about it.
4. **Approvals.** The vault never calls `transferFrom` and never grants approvals, so there is no allowance to drain.

**Live evidence (14 Nov 2026, testnet).** [`scripts/attack-sim.ts`](../scripts/attack-sim.ts) (`npm run attack`) loads **only** the drill account's ECDSA key, never the recovery code or the guardian key, and attacks our account and vault:

| Layer | Attack | Result |
|---|---|---|
| Native | bank send, ECDSA only | refused, pqc code 20 |
| Native | bank send, hybrid with a guessed PQ key | refused, pqc code 21 |
| Native | open an EVM window (ECDSA only / guessed PQ key) | refused, code 20 / 21 |
| Native | register the attacker's PQ key over ours | refused, pqc code 234 |
| EVM | QOR transfer; vault call | refused: "no open EVM authorisation window" |
| Vault (eth_call, as if a window were open) | withdraw with the attacker's own ML-DSA key | `WrongKey()` |
| Vault | owner key + forged/random signature: withdraw, take over, raise limit, freeze | `BadSignature()` |
| Vault | replay a real past owner signature read from the chain | `Expired()` (the nonce also blocks it, Theorem 2) |

The same day, the real flows succeeded on chain with real signatures: deposit, an instant withdrawal, a queued withdrawal, a guardian cancel, a guardian freeze, and a joint unfreeze.

---

## 8. What we do NOT claim

1. **Both PQ keys stolen (A_OG)** means total loss. Any 2-key system shares this.
2. **Stalemate.** If exactly one PQ key is stolen, the honest side and the thief can cancel each other's recovery proposals forever. The funds stay frozen but safe. Breaking the tie would need a third party, which we left out on purpose to keep the trust model small.
3. **H6 monitoring** is needed for Theorem 5. A watchtower that holds a pre-signed freeze reduces the human effort (planned).
4. **Signing what you didn't mean (phishing).** If the owner signs a malicious vault message, it executes. Mitigations:
   * clients rebuild the 384-byte message themselves and show the decoded fields;
   * big amounts wait $D$, so they can still be cancelled.
5. **Precompile governance.** If `pqcVerify` is turned off, the vault fails closed (Lemma 7). Funds are then stuck until it's turned back on. That is a liveness risk, not a safety risk. On mainnet the precompile is not active today, so the vault is testnet-only for now.
6. **Token contracts.** Theorem 1 covers the vault's own logic. A token with admin seizure, fees on transfer or pausing behaves as its own code says.
7. **Lemma 3 covers today's signing formats** (SDK 0.14.0). A future format, or a wallet that signs arbitrary bytes with the account key, is out of scope. Use a dedicated owner key for maximum separation.
8. **Assumptions about the platform.** We assume the Solidity compiler (0.8.28, via-IR) and the chain's EVM are correct. The contract has not been formally verified; these are hand proofs over the source. The QCAI audit (two stages) is planned.
9. **Side channels** on the signer's device are out of scope.

---

## 9. Claims → tests

`npm test` runs **73 tests** in three suites, all on Hardhat's simulated chain:

1. **`test/QDayVault.ts`**: one block per theorem (table below).
2. **`test/Adversarial.ts`**: attacker and edge cases. It covers:
   * other chain id, front-running, a relayer starving the gas, joint/unfreeze replay, deadline boundaries;
   * the queue lifecycle, limit and delay changes, absurd amounts;
   * key replacement (Lemma 6), keys never becoming equal, degenerate new keys;
   * liveness with a lost guardian while frozen;
   * precompiles answering in a malformed format;
   * tokens that return `false` or nothing;
   * an end-to-end run of the CLI's client library, including its refusal to sign when the contract's message differs from its own;
   * 200 random messages where the TypeScript and Solidity encodings must agree byte for byte.
3. **`test/QDayVault.invariant.t.sol`**: fuzz and invariant tests.
   * **Invariant campaign:** 256 runs × 100 random steps per invariant. At each step a random actor is chosen: the honest owner, the honest guardian, an anonymous executor, or the attacker. The attacker uses invented signatures, signatures from its own ML-DSA key, and every signature the honest side ever published (replayed unchanged or tampered with).
   * **Invariants checked after every step:** the attacker never makes a privileged call succeed; attacker addresses never receive a wei; outflow went only to honest recipients and is at most what the owner signed; nothing is paid while frozen; keys never change; settings stay in bounds.
   * **Stateless fuzz:** 1,000 runs each for invented signatures, message shape and injectivity, the daily limit, the delay, and length checks.
   * **A non-vacuity test** that proves the honest paths in the campaign really move money.

**Static analysis:** Slither 0.10+ (via-IR build). It reports no real issues. Every finding is either by design or noise:
* `arbitrary-send-eth`: the recipient is owner-signed (T1).
* `timestamp` and `incorrect-equality`: day buckets and deadlines, which tolerate seconds of drift against `D ≥ 5 min`.
* `low-level-calls`: needed to check return-data length (L7).

Signatures in the TypeScript suites are real ML-DSA-87. Signatures are real ML-DSA-87. The precompile is an oracle mock that only accepts triples the real algorithm has verified (see [`contracts/test/Mocks.sol`](../contracts/test/Mocks.sol)). `npm run probe` checks H3 against the live testnet precompile.

| Claim | Tests (`describe` block in `test/QDayVault.ts`) |
|---|---|
| T1 | "Theorem 1": no-signature, wrong-key and wrong-signature withdrawals revert; every privileged function refuses; relayer independence; no redirection |
| T2 | "Theorem 2": replay, other vault, any changed field, other action, expired, role swap, future nonce |
| L3 | "Lemma 3": 384 bytes, first byte `0xFF` |
| T4 | "Theorem 4": instant vs queued, delay enforced, daily reset, tokens always queued, limit change delayed |
| T5, L6 | "Theorem 5": guardian cancel, freeze blocks all withdrawals, unfreeze needs both, guardian can't withdraw or change settings, recovery kills the old key's items, owner vetoes a malicious guardian |
| L7 | "Lemma 7": inactive precompile, degenerate/short/duplicate keys, `pqcKeyStatus` binding rules |
| T8 | "Liveness and hygiene": no-guardian unfreeze, re-entrancy blocked, bad recipients/tokens refused |
