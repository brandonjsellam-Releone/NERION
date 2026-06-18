# PolarSeek — STATUS

**Phase: P2 complete + hardened; P3 wedge in progress.** Updated 2026-06-18.
**108 tests pass** (`npm run gate`). Runnable: `npm run demo`, `npm run bundle && npm run verify:cli`.

## Milestones

- **P0 Foundations — ✅** SuiteID crypto-agility, hybrid KEMs, ML-DSA-87/SLH-DSA, deterministic CBOR, KATs.
- **P1 Kernel & Capabilities — ✅** Stateless deterministic `decide()`; attenuation-only capabilities (attenuation-never-amplifies property-tested); byte-identical ReplayBundle; TLA⁺ model (authored).
- **P2 Receipts & Transparency — ✅** RFC 6962 Merkle log (inclusion + consistency proofs); PQ receipts (hashes only); **standalone external verifier CLI** — verifies signature + log inclusion with no trust in the issuer or operator.
- **P2 hardening — ✅** RATS attestation (software root real; TEE stubs); **action-bound PermitTokens** closing the replay finding; `PolarSeekNode` orchestrating the planes.

## What is real and runnable today

| Module | State |
|---|---|
| `crypto/` `capabilities/` `kernel/` `receipts/` `translog/` `attest/` `planes/` | Implemented, tested (108) |
| `tools/cleanroom-lint.mjs` | CI non-infringement gate (F1–F8) |
| `npm run demo` | End-to-end T2 governed-payment trace |
| `npm run bundle` / `verify:cli` | Portable receipt + **independent external verification** |
| `kernel/spec/*.tla` | Formal safety model (authored, not machine-checked) |

## Honest caveats (deployment maturity = Local/Private dev)

- **Not production-hardened.** No Rust hot-path (`<1 ms` is a target); software attester only (real TEE/HSM pending); in-memory single-operator log (no gossip/mirroring/ledger anchoring yet); no ZK selective disclosure yet; TLA⁺ not machine-checked.
- **Design-around ≠ legal opinion.** FTO required before any public non-infringement claim ([FTO_TODO.md](./FTO_TODO.md)). See [DEPLOY.md](./DEPLOY.md) for the full production gap list.

## Next actions (toward the deployable wedge & beyond)

1. **SDK + MCP/LangChain adapter** (`sdks/`): wrap high-risk agent tool-calls (payments, infra, data export/delete, deploy, key rotation) through `PolarSeekNode.admit` — the operational agent integration for pilots.
2. **Transparency hardening**: multi-operator gossip + split-view detection; ZK proof for one property ("amount < threshold"); persistent log.
3. **Provision Rust** for the hot-path; machine-check `kernel/spec` (TLAPS/Lean); wire official NIST ACVP vectors. Then P3 ledger/settlement/governance.

## Council

P0 council (Gemini/watsonx/DeepSeek) PASS with corrections — [council/P0-verdicts.md](./council/P0-verdicts.md). The DeepSeek #1 replay finding is now addressed (action-bound permits). Re-run the full council before any external claim / pilot sign-off.
