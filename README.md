# Q-Day Vault

A QoreChain EVM vault whose funds and settings change **only with a post-quantum (ML-DSA-87) signature**, verified on chain by the `pqcVerify` precompile. The vault never trusts `msg.sender`, so a stolen ECDSA key, or one broken by a quantum computer, moves nothing.

Entry for **Build Before Q-Day** (Post-Quantum dApp category + Q-Day Drill).

- **What exactly we claim, and the proofs:** [docs/SECURITY_PROOFS.md](docs/SECURITY_PROOFS.md)
- **Contract:** [contracts/QDayVault.sol](contracts/QDayVault.sol)
- **Tests (each mapped to a theorem):** [test/QDayVault.ts](test/QDayVault.ts)

## Features

- ML-DSA-87 authorisation for every withdrawal and settings change (`pqcVerify`, `0x…0A01`)
- Optional binding of the owner key to the account's registered QoreChain key (`pqcKeyStatus`, `0x…0A02`, with proof of possession)
- Owner + guardian keys with separate nonces
- Daily instant limit per asset; larger withdrawals wait in a public queue for a delay
- Time-locked settings, cancel, freeze (either key), unfreeze (both keys), guardian recovery with epoch invalidation
- Relayer-friendly: anyone can submit a signed action
- Fails closed if the precompile is inactive or answers anything but `true`

## Run

```sh
npm install
npm test          # unit tests, real ML-DSA-87 signatures, simulated chain
npm run probe     # read-only check of the live testnet pqcVerify precompile
npm run vault             # list CLI commands
```

## Testnet runbook (drill account)

```sh
npm run vault -- init                 # throwaway account (.env) + guardian key (secrets/), both gitignored
# fund the printed qor1... address (faucet), then:
npm run vault -- register             # ML-DSA-87 key, with proof of possession
npm run vault -- window-open deploy   # unscoped window, only for the deployment
npm run vault -- deploy 1 3600        # 1 QOR/day instant limit, 1 h delay; owner key bound via pqcKeyStatus
npm run vault -- window-open vault 3  # window scoped to allowed_targets = [vault], room for a 3 QOR deposit
npm run vault -- deposit 3
npm run vault -- withdraw 0x... 0.1   # ML-DSA-signed withdrawal
npm run vault -- window-close         # no window may be open during the drill
npm run vault -- status
npm run vault -- drill-tx             # drill day: hybrid-signed self-transfer, submit its hash
```

## Credits

- Project scaffold and `scripts/window.ts` from [qorechain/build-before-qday](https://github.com/qorechain/build-before-qday) `workshop-1/01-qday-counter` (Apache-2.0).
- [`@qorechain/sdk`](https://www.npmjs.com/package/@qorechain/sdk) and [`@qorechain/evm`](https://www.npmjs.com/package/@qorechain/evm) for ML-DSA-87 signing and QoreChain helpers; Hardhat 3 + viem.

## License

Apache-2.0
