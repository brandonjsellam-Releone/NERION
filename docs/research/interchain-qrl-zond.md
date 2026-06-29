<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nerion ⇄ QRL Zond interchain — concept to concrete

**Status:** design + reference implementation (the Solidity contract is **not compiled/deployed in
this repo** — no Solidity toolchain here; the TS encoder IS tested). 2026-06-30. Builds on
[`pq-pos-interop-convergence.md`](pq-pos-interop-convergence.md) §3.

## The breakthrough: a shared signature scheme

QRL 2.0 / **Zond** (testnet v2, Q1 2026) signs its **entire stack with ML-DSA-87 (Dilithium-5,
FIPS-204)** — go-qrllib, go-zond, Qrysm, deposit contracts — and its **Hyperion** compiler (a
post-quantum superset of Solidity) **natively verifies lattice signatures** on its **QRVM** (an EVM
fork), in line with the proposed **EIP-8051 ML-DSA verification precompile**.

**Nerion's consensus attestations are also ML-DSA-87.** So there is **no signature translation**: a
contract on QRL Zond can verify Nerion's *existing* finality attestations **natively and cheaply**.
That is the concrete substrate the interchain was missing.

## The end-to-end flow (concrete)

```
Nerion finalizes a block  ──exportFinalityProof()──▶  PortableFinalityProof  (ledger/src/portable.ts)
                                                          │
                                   finalityProofToEvmInput()  (ledger/src/evm.ts, TESTED)
                                                          │  0x-hex calldata
                                                          ▼
                          NerionFinalityVerifier.verifyFinality(...)  on QRL Zond  (QRVM/Hyperion)
                                                          │  native ML-DSA-87 precompile per attestation
                                                          ▼
                          returns finalized = (attestingStake·den ≥ num·totalStake)
                                                          │
                            a Zond dApp / bridge acts on a PQ-verified Nerion finality
```

This replaces the trusted-multisig bridge model the interoperability literature shows lost ~$1B
(Wormhole + Ronin): the trust root is a **>2/3 ML-DSA-87 stake quorum over a transparency-logged
block, verified by the destination chain itself** — not a custodial committee.

## What is built here

- **`ledger/src/evm.ts` — `finalityProofToEvmInput(proof, trustedSet)`** (TESTED, `ledger/test/evm.test.ts`):
  packages a portable finality proof into the 0x-hex shape the contract consumes. It emits the
  `setId` and each attestation's signed message **exactly** as Nerion's own `consensusSetId` /
  `attestMessage` produce them, so an on-chain recomputation agrees byte-for-byte.
- **`contracts/NerionFinalityVerifier.sol`** (REFERENCE, uncompiled here): the destination verifier.
  Recovers each attestor's stake, dedups distinct validators, verifies each ML-DSA-87 signature via
  the QRVM precompile, and returns finalized iff a >2/3 stake quorum signed — the gas-sensitive core.

## Honest open items (the remaining integration work)

1. **On-chain message recomputation (soundness).** `setId` and the attestation message must be
   recomputed *by the contract* from the validator set + header, not trusted from the relayer.
   Nerion signs `dCBOR(['polarseek-attest-v2', suite, height, hash, setId])` and
   `setId = SHAKE256(dCBOR([...sortedValidators, epoch]))`. Two options: **(A)** port the minimal,
   fixed-shape dCBOR + SHAKE256 into Hyperion; **(B)** add a Nerion EVM-native attestation profile
   (keccak/abi.encode) signed alongside the dCBOR one so the contract recomputes cheaply. The
   reference currently enforces all attestations agree on a caller-supplied message; choosing A or B
   is the next step.
2. **Compile + test on QRVM.** Needs the Zond toolchain (Hyperion compiler, the live ML-DSA-87
   precompile address, a testnet RPC at `test-zond.theqrl.org`). Out of scope for this TS/Rust repo.
3. **Input caps** on `validators.length` / `attestations.length` (decode-side DoS), mirroring the
   off-chain `verifyFinalized` caps.

## Not a claim

This does not assert Nerion interoperates with QRL Zond today, that the contract is audited or
deployed, or that Nerion is FIPS-validated. It is a concrete, grounded design + a tested off-chain
encoder + a reference verifier, with the remaining work named explicitly.

## Sources

- [QRL launches testnet v2 for its post-quantum, EVM-friendly blockchain](https://www.theqrl.org/press/qrl-launches-testnet-v2-for-its-postquantum-evmfriendly-blockchain/)
- [QRL docs](https://docs.theqrl.org/) · [Zond testnet docs](https://test-zond.theqrl.org)
- [EIP-8051: Precompile for ML-DSA signature verification](https://eips.ethereum.org/EIPS/eip-8051)
- [QRL roadmap](https://www.theqrl.org/roadmap/) · [Project Zond AMA (Hyperion / QRVM)](https://www.theqrl.org/blog/how-qrls-project-zond-will-onboard-the-next-wave-of-developers-ama-with-lead-dev-kaushal/)
