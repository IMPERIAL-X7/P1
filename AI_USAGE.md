# AI usage

Q-Day Vault was built by one student working with an AI coding agent. This file explains the workflow honestly: what the AI did, what the human did, and how AI output was checked before it was trusted.

## Tools

- **Claude Code** (Anthropic, Claude Opus models), used as an agent in the terminal and in VS Code. It could read the repo, run commands, run the tests and talk to the QoreChain testnet.
- No other AI tools were used.

## Workflow

1. **Context first.** The hackathon rules, the category requirements and the drill rules were written into a handoff note. The agent read the official QoreChain sources before writing any code: the `qorechain-docs` repo, the `build-before-qday` workshop examples, and the SDK.
2. **Design in conversation.** The human set the goal ("funds must survive a leaked ECDSA key") and questioned the design. For example, they asked: "wouldn't everyone just build the same two-key contract?" That question led to the expanded feature set: the timelock, the guardian, the freeze, the daily limit and safe key rotation.
3. **Proofs before trust.** The human asked for the security claims to be written as precise, readable proofs. The result is [docs/SECURITY_PROOFS.md](docs/SECURITY_PROOFS.md). Each claim is linked to the tests that check it.
4. **De-risk on the real chain.** Before the contract was written, the agent probed the live `pqcVerify` precompile ([scripts/probe-pqc.ts](scripts/probe-pqc.ts)) to find out exactly which bytes it verifies. The docs left this open.
5. **Build, then attack.** The agent wrote the contract, the CLI and the tests, and then attacked its own design: adversarial tests, fuzz/invariant tests, Slither, and a live attack simulator ([scripts/attack-sim.ts](scripts/attack-sim.ts)).
6. **Human review and commits.** The human reviewed the changes, made every commit, and did every step that needs their identity: the faucet, the website, project registration and the drill.

## What was AI-generated

Most of the code and text was written by the AI agent:

- `contracts/QDayVault.sol` and the test mocks in `contracts/test/`
- the scripts in `scripts/`: the CLI, the shared libraries, the precompile probe and the attack simulator. `scripts/window.ts` is adapted from the official workshop template.
- the tests in `test/`: unit, adversarial, and Solidity fuzz/invariant
- `docs/SECURITY_PROOFS.md`, `README.md` and the cover image (`docs/cover.html`, rendered to PNG)

## What the human did

- Chose the project and the threat model it defends against, and decided the scope and priorities around exam deadlines.
- Pushed the design beyond a minimal two-key vault, and asked for formal, judge-readable proofs.
- Asked for testing "from all points of view" and set the bar that the architecture must not be breakable.
- Ran the on-chain steps that need a person: faucet funding, website registration, the project page and drill entry.
- Reviewed and committed all work. Kept the secrets (keys, recovery codes) out of git.

## How AI output was verified

We did not take the AI's word for anything. Every claim was checked by something other than the AI's own reasoning:

- **Real cryptography in tests.** The tests sign with real ML-DSA-87 keys from `@qorechain/sdk`. The mock precompile accepts only signatures the SDK actually produced, so the tests can't pass with fake signatures.
- **Tests that can fail.** There are 73 tests. The invariant handler includes a non-vacuity check (`test_handlerIsNotVacuous`), which shows the fuzzer really drove the vault through its actions.
- **Our own tests found real bugs in the AI's design, which were then fixed.** First, replacing the guardian did not cancel its queued actions. Second, setting an old key back revived the actions it had signed earlier. Both were fixed with a per-role key version counter, and both have regression tests.
- **Live evidence.** Every flow was run on QoreChain testnet. The attack simulator, using only the ECDSA key, had all 14 attacks blocked. See the README and §7 of the proofs.
- **Static analysis.** Slither findings were triaged one by one in the proofs document.
