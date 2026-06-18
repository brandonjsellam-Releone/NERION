# PolarSeek — STATUS

**Phase: P1 (Kernel & Capabilities) — substantially complete.** Updated 2026-06-18.

## Milestones

### P0 (Foundations) — ✅ MET
Hybrid KEM + ML-DSA round-trip + KATs pass. `crypto/` green.

### P1 (Kernel & Capabilities) — ✅ exit criteria met (formal model authored)
> "Two independent runs of the same ReplayBundle yield identical decision + receipt hash; formal properties pass."

- **Byte-identical replay:** `kernel/test/replay.test.ts` — same ReplayBundle ⇒ identical decision + receipt hash (unit + fast-check property).
- **Formal properties (property-tested):** attenuation-never-amplifies, default-deny, allow-implies-authorization, determinism. Modeled in `kernel/spec/PolarSeekKernel.tla` (authored; **not yet machine-checked** — no TLA⁺ toolchain locally; executable counterpart is green).
- **Total: 82 tests pass** (`npm run gate`: clean-room lint + prettier + tsc + vitest).

## (a) What changed since P0

- **`capabilities/`** — typed, PQ-signed (ML-DSA-87) grants; **attenuation-only** UCAN/macaroon-style delegation (`narrow` clamps to the parent so a child can never broaden); chain verification against explicit trusted roots; **default-deny resolver** with per-action ceiling, rolling aggregate cap (enforced via the **signed scalar**, never in-kernel state), counterparty allowlist, risk-tier ceiling, validity window, and holder binding.
- **`kernel/`** — stateless, deterministic `decide()` (pure function, fail-closed, no clock/IO/state); deterministic risk-tiering (T0–T3) with tier→obligations; pinned **evaluator version** hashed into every decision; **ReplayBundle** for byte-identical re-derivation.
- **`kernel/spec/`** — TLA⁺ safety model + honest status note.

## (b) Test / council results

- Tests: **82/82** pass; format + typecheck + clean-room lint clean.
- Council (P0): PASS with corrections applied — [council/P0-verdicts.md](./council/P0-verdicts.md). The DeepSeek-flagged **PermitToken replay** and **HMAC key management** are P1/P2 kernel-integration items (the kernel itself is now built; binding the PermitToken to a single-use attestation nonce + audience/action is the next step). Re-run the full council before P1 sign-off.

## (c) Risks / decisions

- ADR-0001 (crypto suite) · ADR-0002 (TS reference + KEM pairing) · ADR-0003 (repo location).
- **Honest caveats:** the formal model is authored, **not machine-checked** (no toolchain); `<1 ms` hot-path is a **target** (no Rust yet); Planes 2–3 (receipts/translog/ledger/attest) remain unbuilt; attestation binding for PermitTokens is not yet wired. Design-around ≠ legal opinion — FTO required ([FTO_TODO.md](./FTO_TODO.md)).

## (d) Next 3 actions

1. **P2 receipts + transparency log:** batch ML-DSA-87 receipts over decisions (reuse `signEnvelope` + the ReplayBundle `receiptHash`), Merkle-anchor to a SCITT-style append-only log with inclusion/consistency proofs; an external CLI verifies a receipt with no issuer trust.
2. **Attestation + PermitToken hardening:** wire the Plane-1 PermitToken to a single-use attestation nonce + audience/action binding (closes the council's #1 finding); per-resource HKDF-derived MAC keys.
3. **End-to-end T2 demo** (flagship): action intent → admission decision → PermitToken → ML-DSA receipt → verifiable transparency-log entry. Provision Rust + machine-check the TLA⁺ spec in parallel as toolchains allow.

## Backlog

- Official NIST ACVP KAT vectors; HQC (on FIPS publication) + Falcon (on FIPS 206); SLSA provenance; GitHub remote + CI execution; machine-check `kernel/spec` (TLAPS/Lean).
