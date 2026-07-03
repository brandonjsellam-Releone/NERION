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

The **relayer-substitution gap is closed (option B implemented)** and the profile is hardened against
cross-chain replay + malformed-input divergence: an EVM-native, keccak256-only attestation profile the
contract recomputes on-chain, with the destination bound into the signed message.

- **`ledger/src/evmprofile.ts`** (TESTED — `evmprofile.test.ts` 16 cases + `evmprofile-reconfig.property.test.ts`
  + `evmprofile-vectors.test.ts`) — the EVM-native profile + the **canonical TS reference verifier**:
  - `evmSetId(set)` / `evmAttestMessage(...)` — a keccak256 fold (no SHAKE, no CBOR) an EVM
    reproduces cheaply: `evmSetId = keccak(fold over keccak(pubkey)‖uint256(stake)‖keccak(vrf))`,
    `evmMessage = keccak(keccak(tag)‖keccak(suite)‖uint256(chainId)‖verifier(20)‖uint256(height)‖blockHash(32)‖setId(32))`.
    The message binds the **destination `chainId` + `verifier` address** (= Solidity `block.chainid` +
    `address(this)`), so a proof for one chain/deployment can not be replayed on another.
  - `signEvmAttestation(...)` — a validator's ML-DSA-87 signature over the profile message (opt-in,
    co-signed alongside consensus; the native dCBOR/SHAKE256 path is untouched).
  - `verifyEvmFinality(...)` — **recomputes setId + message from the trusted set** (NOT from a
    relayer), verifies each ML-DSA-87 signature, dedups distinct members, and finalizes iff a ≥2/3
    stake quorum signed. This is the byte-for-byte spec the contract must match. It **never throws** —
    every malformed input fails closed to `{finalized:false}`: sub-quorum, tampered sig, duplicated
    signer, a different set, an epoch change, a **different chainId/verifier** (replay), a non-32-byte
    blockHash, a non-integer/out-of-range height, a malformed member pubkey, a `u256` overflow, a
    duplicate-pubkey set (denominator-inflation), and an over-cap attestation flood. Integers are
    width-checked (no mod-2²⁵⁶ aliasing → no cross-height/epoch replay), the set is canonicalized
    (sorted by decoded pubkey bytes, duplicates rejected) to match the contract's fold order.
- **`contracts/NerionFinalityVerifier.sol`** (REFERENCE, uncompiled here): recomputes `evmSetId`
  (keccak fold, ascending-pubkey + duplicate-reject) and `evmMessage` ON-CHAIN, enforces the
  destination binding (`require(chainId == block.chainid)`, `require(verifier == address(this))`),
  caps `validators.length` / `attestations.length`, and verifies each ML-DSA-87 signature over the
  recomputed message via the QRVM precompile — so a relayer cannot substitute the message or the set,
  and the proof cannot cross chains. The keccak fold is byte-identical to `evmprofile.ts`, pinned by
  the golden vectors in `contracts/test/evm-profile-vectors.json`.
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
3. **Pin the ML-DSA-87 precompile message framing.** `evmMessage` produces a bare 32-byte keccak
   digest; the TS reference signs it with **pure** ML-DSA (FIPS 204 §5.2), which internally frames the
   message as `0x00 ‖ len(ctx)=0x00 ‖ msg`. Before deploy, confirm whether the QRVM / EIP-8051
   `verify` precompile expects the bare digest (and applies the domain prefix itself) or a pre-framed
   input, and lock a cross-impl KAT. A mismatch fails **closed** (all attestations rejected), not
   open, but must be reconciled for the profile to verify at all. (Decode-side input caps are now
   enforced in-contract and in `evmprofile.ts`; the earlier open item is closed.)

## Soundness scope (precise)

The profile is **sound against relayer message/set substitution** (on-chain recomputation) **and
against cross-chain / cross-deployment replay** (chainId + verifier binding) **and against the
malformed-input and integer-aliasing classes** enumerated above (fail-closed + width-checked +
canonicalized). It is **not** yet end-to-end verified on QRVM: items 1–3 above (compile, co-signing
rollout, precompile-framing pin) remain. "Sound" here means those specific properties, not a
completed audit.

**Accountability (LEDGER-EVM-ACCT-001 — now implemented).** Beyond the **finality quorum** (≥2/3
ML-DSA-87 stake attestation over the block), the profile now also provides **accountable slashing** on
the interchain surface: `evmprofile.ts` exports `detectEvmEquivocations` + `verifyEvmEquivocationProof`,
the interchain analogue of the native `equivocation.ts`. A validator that co-signs conflicting
EVM-profile attestations for two distinct blocks at the **same height** produces a slashable
`EvmEquivocationProof`; the verifier recomputes both messages from the trusted set + target (never
trusts a relayer) and rejects same-block, non-member, forged-sig, and stale cross-epoch proofs. No
`round` is bound because Nerion attestations are **one-per-height by design** — so same-height
double-signing is the offense and honest one-block-per-height behavior across DIFFERENT heights is not
(LEDGER-EQUIV-001 parity), exactly matching the native path. Not a live threat regardless (forging
conflicting finality needs ≥2/3 of stake to co-sign, already breaking honest-majority), but the
accountability guarantee now extends to the exported finality surface, not only native consensus.
On-chain, the reference `NerionFinalityVerifier.sol` now exposes the matching `verifyEquivocation`
(same recompute-from-trusted-set + destination binding), so the TS reference and the reference contract
stay in lock-step; compiling + fuzzing it on QRVM remains tracked with the compile/precompile-pin items.

## Not a claim

This does not assert Nerion interoperates with QRL Zond today, that the contract is audited or
deployed, or that Nerion is FIPS-validated. It is a concrete, grounded design + a tested off-chain
encoder + a reference verifier, with the remaining work named explicitly.

## Sources

- [QRL launches testnet v2 for its post-quantum, EVM-friendly blockchain](https://www.theqrl.org/press/qrl-launches-testnet-v2-for-its-postquantum-evmfriendly-blockchain/)
- [QRL docs](https://docs.theqrl.org/) · [Zond testnet docs](https://test-zond.theqrl.org)
- [EIP-8051: Precompile for ML-DSA signature verification](https://eips.ethereum.org/EIPS/eip-8051)
- [QRL roadmap](https://www.theqrl.org/roadmap/) · [Project Zond AMA (Hyperion / QRVM)](https://www.theqrl.org/blog/how-qrls-project-zond-will-onboard-the-next-wave-of-developers-ama-with-lead-dev-kaushal/)
