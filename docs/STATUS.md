# PolarSeek — STATUS

**Phase: P0 (Foundations).** Updated 2026-06-18.

## P0 exit criterion — ✅ MET

> "Hybrid KEM + ML-DSA round-trip + KATs pass."

`crypto/` is implemented and **green**: `npm run gate` runs the clean-room linter,
prettier check, `tsc`, and **51 vitest tests** (hybrid KEM round-trips, ML-DSA-87
& SLH-DSA sign/verify, AES-256-GCM/HMAC/SHAKE, deterministic-CBOR determinism,
SuiteID negotiation + downgrade resistance, signed envelopes + PermitTokens, and
deterministic KAT vectors).

## (a) What changed

- Monorepo scaffolded at `C:\Users\User\polarseek` (short path — ADR-0003); git on `main`; CI workflow (`.github/workflows/ci.yml`).
- `crypto/` reference implementation in TypeScript over audited `@noble` libs (ADR-0002): SuiteID registry + negotiation, hybrid KEMs (X-Wing; ML-KEM-1024+P-384), ML-DSA-87, SLH-DSA-SHAKE-256f, AES-256-GCM, HMAC-SHA-384, SHA3/SHAKE256, deterministic CBOR, SuiteID-bound signed envelopes, hot-path PermitTokens. HQC + Falcon are honest `NotImplementedError` agility stubs.
- Deterministic KAT vectors (`crypto/vectors/`), reproducible via `_gen.mjs`; CI fails on drift.
- Clean-room CI linter (`tools/cleanroom-lint.mjs`) enforcing CLEANROOM F1–F8.
- Docs: THREAT_MODEL, CLEANROOM (with the extracted SIGA claim map, anchor patent **US 9,607,214 B2**), DESIGN_AROUND, FTO_TODO, PRIOR_ART_NOTES, ADR-0001/0002/0003, council verdicts.

## (b) Test / council results

- **Tests:** 51/51 pass; format + typecheck + clean-room lint clean.
- **Council (Gemini / watsonx / DeepSeek):** PASS with corrections applied — see [council/P0-verdicts.md](./council/P0-verdicts.md). Gemini's "unverifiable" flags on 2025–26 NIST items were **overruled by primary-source re-verification** (SP 800-227 final 2025-09-18; HQC selected 2025-03-11; SP 800-230 IPD 2026-04-13). Fixed: HQC FIPS-number precision, PS-1 Cat-3 floor labeling, public-verifiability attributed to Plane 2.

## (c) Risks / decisions

- ADR-0001 (crypto suite & standards) · ADR-0002 (TS reference + KEM pairing) · ADR-0003 (repo location).
- **Honest caveats:** only `crypto/` is built; `<1 ms` is a **target**, Planes 2–3 are **unbuilt**; the Rust hot-path is **deferred** (no toolchain). PermitToken replay defense and HMAC key management are **P1 kernel requirements** (already in the threat model). Engineering design-around is **not** a legal opinion — FTO required ([FTO_TODO.md](./FTO_TODO.md)).

## (d) Next 3 actions

1. **P1 kernel**: stateless deterministic admission kernel + typed capabilities (UCAN/macaroon attenuation) + ReplayBundle (byte-identical replay), with the PermitToken replay defenses (single-use attestation nonce + audience/action binding) the council flagged.
2. **Provision Rust** (`rustup`) and port `crypto/`+`kernel/` to the same SuiteID/wire contract for the hot path; add differential tests (TS ↔ Rust) and wire official **NIST ACVP** KAT vectors.
3. **Formal spec** (`kernel/spec/`, TLA+/Lean): soundness, attenuation-never-amplifies, receipt-implies-authorization; then re-run the full council before P1 exit.

## KAT / TODO backlog

- Wire official NIST ACVP KAT vectors alongside the deterministic regression vectors.
- Implement HQC (on FIPS-207 publication) and re-evaluate Falcon (on FIPS 206 final).
- GitHub remote + CI execution; SLSA provenance + reproducible-build attestation.
