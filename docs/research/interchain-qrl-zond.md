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

The **soundness gap is now closed (option B implemented)**: an EVM-native, keccak256-only
attestation profile the contract recomputes on-chain.

- **`ledger/src/evmprofile.ts`** (TESTED, `ledger/test/evmprofile.test.ts`, 7 tests) — the EVM-native
  profile + the **canonical TS reference verifier**:
  - `evmSetId(set)` / `evmAttestMessage(...)` — a keccak256 fold (no SHAKE, no CBOR) an EVM
    reproduces cheaply: `evmSetId = keccak(fold over keccak(pubkey)‖uint256(stake)‖keccak(vrf))`,
    `evmMessage = keccak(keccak(tag)‖keccak(suite)‖uint256(height)‖blockHash‖setId)`.
  - `signEvmAttestation(...)` — a validator's ML-DSA-87 signature over the profile message (opt-in,
    co-signed alongside consensus; the native dCBOR/SHAKE256 path is untouched).
  - `verifyEvmFinality(...)` — **recomputes setId + message from the trusted set** (NOT from a
    relayer), verifies each ML-DSA-87 signature, dedups distinct members, and finalizes iff a >2/3
    stake quorum signed. This is the byte-for-byte spec the contract must match. Fully tested:
    finalizes a real quorum; fails closed on sub-quorum, tampered sig, duplicated signer, a different
    set, and an epoch change.
- **`contracts/NerionFinalityVerifier.sol`** (REFERENCE, uncompiled here): now **sound** — it
  recomputes `evmSetId` (keccak fold, sorted-pubkey check) and `evmMessage` ON-CHAIN and verifies
  each ML-DSA-87 signature over the recomputed message via the QRVM precompile, so a relayer cannot
  substitute the message or the set. The keccak fold is byte-identical to `evmprofile.ts`.
- **`ledger/src/evm.ts` — `finalityProofToEvmInput(...)`** (TESTED): the dCBOR-view packer (option-A
  reference / relayer convenience), retained.

## Honest open items (the remaining integration work)

1. **Compile + test on QRVM.** The contract is byte-matched to the tested TS reference but needs the
   Zond toolchain to compile (Hyperion), the live ML-DSA-87 precompile address, and a testnet RPC at
   `test-zond.theqrl.org`. Out of scope for this TS/Rust repo.
2. **Validator co-signing rollout.** `signEvmAttestation` is the primitive; wiring it into the
   validator's per-block flow (so the evm-profile signature is collected alongside the native
   attestation) is a small, opt-in deployment step — deliberately NOT wired into the consensus hot
   path here.
3. **Input caps** on `validators.length` / `attestations.length` on-chain (decode-side DoS),
   mirroring the off-chain `verifyFinalized` caps.

## Not a claim

This does not assert Nerion interoperates with QRL Zond today, that the contract is audited or
deployed, or that Nerion is FIPS-validated. It is a concrete, grounded design + a tested off-chain
encoder + a reference verifier, with the remaining work named explicitly.

## Sources

- [QRL launches testnet v2 for its post-quantum, EVM-friendly blockchain](https://www.theqrl.org/press/qrl-launches-testnet-v2-for-its-postquantum-evmfriendly-blockchain/)
- [QRL docs](https://docs.theqrl.org/) · [Zond testnet docs](https://test-zond.theqrl.org)
- [EIP-8051: Precompile for ML-DSA signature verification](https://eips.ethereum.org/EIPS/eip-8051)
- [QRL roadmap](https://www.theqrl.org/roadmap/) · [Project Zond AMA (Hyperion / QRVM)](https://www.theqrl.org/blog/how-qrls-project-zond-will-onboard-the-next-wave-of-developers-ama-with-lead-dev-kaushal/)
