# PolarSeek — STATUS

**Phase: P2 (Receipts & Transparency) — core complete.** Updated 2026-06-18.

## Milestones

- **P0 (Foundations) — ✅** Hybrid KEM + ML-DSA round-trip + KATs. `crypto/` green.
- **P1 (Kernel & Capabilities) — ✅** Byte-identical ReplayBundle; attenuation-never-amplifies + default-deny property-tested; TLA⁺ model authored.
- **P2 (Receipts & Transparency) — ✅ core** "An external verifier checks a receipt's signature + log inclusion with no trust in the issuer or the log operator." Demonstrated end-to-end (`npm run demo`).

**96 tests pass** (`npm run gate`: clean-room lint + prettier + tsc + vitest).

## (a) What changed since P1

- **`translog/`** — RFC 6962-style Merkle transparency log: leaf/node domain separation, Merkle root, **inclusion proofs** and **consistency (append-only) proofs**, verified by Trillian-style decomposition. Exhaustively tested for all indices/sizes 1–16 plus tamper/rewrite rejection. `TransparencyLog` append-only operator + operator-untrusted `checkInclusion`/`checkConsistency`.
- **`receipts/`** — PQ-signed (ML-DSA-87) receipts committing **hashes only** (intent/capability/policy/input/decision) + jurisdiction/tier/suite/timestamp; **no PII, no payloads**. `verifyReceiptInclusion()` = full external verification trusting only the issuer key + a gossiped root.
- **End-to-end T2 demo** (`receipts/test/e2e.test.ts`, `npm run demo`): intent → admission decision → PermitToken → deterministic replay → PQ receipt → transparency-log anchoring → independent external verify (PASS), plus a DENY control.

## (b) Test / council results

- Tests: **96/96** pass; format + typecheck + clean-room lint clean.
- Council (P0): PASS with corrections — [council/P0-verdicts.md](./council/P0-verdicts.md). Re-run the full council before P2 sign-off / any public claim.

## (c) Risks / decisions

- ADR-0001/0002/0003 stand. **Honest caveats:** the external verifier exists as a library function + demo, not yet a packaged standalone CLI binary; the log is an in-memory reference (no multi-operator gossip/mirroring or ledger anchoring yet); ZK selective disclosure not yet built; PermitToken↔attestation binding still pending (P2 hardening); TLA⁺ model not machine-checked; `<1 ms` hot-path is a target (no Rust). Design-around ≠ legal opinion — FTO required ([FTO_TODO.md](./FTO_TODO.md)).

## (d) Next 3 actions

1. **Attestation + PermitToken hardening** (`attest/`): RATS verifier interface + bind the Plane-1 PermitToken to a single-use attestation nonce + audience/action (closes the council's #1 finding); per-resource HKDF-derived MAC keys.
2. **Transparency hardening**: standalone `verify-receipt` CLI; multi-operator gossip + split-view detection; ZK proof for one property ("amount < threshold") with selective disclosure.
3. **Provision Rust** for the hot-path kernel/crypto (differential tests vs the TS contract) and **machine-check** `kernel/spec` (TLAPS/Lean). Wire official NIST ACVP vectors.

## Backlog

- HQC (on FIPS publication) + Falcon (on FIPS 206); SLSA provenance; GitHub remote + CI execution; P3 ledger + settlement + governance.
