# Nerion

_Renamed from **Post‑Quant PolarSeek** (2026‑06‑20) — same open, post‑quantum execution‑governance protocol;
concept and FTO design‑around unchanged._

**An open, post-quantum-native, decentralized execution-governance protocol for
AI/agent _actions_.** Nerion lets agents act — but only within provable,
auditable, least-privilege boundaries, with post-quantum, regulator-ready
evidence anyone can verify.

> **Govern the verb, never the eye.** Nerion governs typed **actions**
> (tool-calls / API requests / transaction intents). It never touches
> perception — no camera frames, no feature decomposition, no object tracking,
> no zone occupancy. This is both the technical thesis and the design-around
> boundary vs. the patented "Sovereign OS / Commit-Point Gate" family. See
> [docs/CLEANROOM.md](docs/CLEANROOM.md) and [docs/DESIGN_AROUND.md](docs/DESIGN_AROUND.md).

> ⚠️ **FTO gate:** design-around is engineering intent, **not** a legal
> non-infringement opinion. No public non-infringement claim or launch before a
> patent-counsel FTO opinion is on file — [docs/FTO_TODO.md](docs/FTO_TODO.md).

## Architecture (three planes)

| Plane | Role | Latency | Crypto |
|---|---|---|---|
| **1 — Hot Admission** | Stateless deterministic kernel → short-lived **PermitToken** | <1 ms p50 (target) | HMAC-SHA-384 MAC, no per-action PQ signing |
| **2 — Nearline Assurance** | Batched **ML-DSA-87** receipts → Merkle → SCITT-style transparency log | ~1–10 s | ML-DSA-87, hybrid KEM transport |
| **3 — Offline Settlement** | Pure-PoS ledger, threshold/MPC governance, long-term roots | s–min | SLH-DSA / LMS / XMSS |

Risk tiers **T0–T3** select how much assurance runs synchronously.

## Status — P0–P4 complete + hardened ✅ (Local/Private dev-deployable)

All planes are implemented in TypeScript over audited `@noble` libraries
(ADR-0002), with **297 passing tests** and a **21/21 conformance report**.
`crypto/`, `capabilities/`, `kernel/`, `receipts/`, `translog/`, `attest/`,
`planes/`, `ledger/` (pure-PoS + VRF private sortition), `governance/`,
`disclosure/` (zero-knowledge), `settlement/`, `keystore/`, and `conformance/` are
all built and tested. The kernel is stateless/deterministic, PermitTokens are
action-bound, and an external CLI verifies a receipt's signature + transparency-log
inclusion with no operator trust. The novel cryptographic *compositions* layered on
`@noble` are **UNAUDITED**, and the ZK layer's **soundness is classical** (discrete‑log — a
transitional, not‑yet‑PQ leg; the commitment's *hiding* is PQ) — see the claim‑by‑claim
[docs/ASSURANCE.md](docs/ASSURANCE.md) and [docs/AUDIT_PACKAGE.md](docs/AUDIT_PACKAGE.md).
Deployment maturity is **Local/Private dev** — four external launch gates remain
([docs/LAUNCH_READINESS.md](docs/LAUNCH_READINESS.md)).

```bash
npm ci
npm run gate          # clean-room lint + prettier + tsc + 297 tests
npm run conformance   # certification report → 21/21 CONFORMANT
npm run demo          # end-to-end T2 governed-payment trace
npm run build && npm run bundle && npm run verify:cli   # independent receipt verification
```

## What's real today

- **`crypto/`** — `SuiteID` registry + negotiation; hybrid KEMs (X-Wing, and
  ML-KEM-1024+P-384 for CNSA-2.0 Cat-5); ML-DSA-87 & SLH-DSA signatures;
  AES-256-GCM / HMAC-SHA-384 / SHA3-SHAKE256; deterministic (dCBOR) canonical
  encoding; SuiteID-bound signed envelopes + hot-path PermitTokens; deterministic
  KAT vectors. HQC and Falcon are honest `NotImplementedError` agility stubs.
- **`tools/cleanroom-lint.mjs`** — CI gate rejecting forbidden perception/stateful
  signals (CLEANROOM F1–F8) in the admission path.
- **`docs/`** — threat model, clean-room map, design-around strategy, ADRs, FTO.

## Documentation

- **[ASSURANCE.md](docs/ASSURANCE.md) — claim‑by‑claim evidence tiers (what's proven vs. tested vs. not yet established).**
- [STATUS.md](docs/STATUS.md) · [THREAT_MODEL.md](docs/THREAT_MODEL.md) ·
  [CLEANROOM.md](docs/CLEANROOM.md) · [DESIGN_AROUND.md](docs/DESIGN_AROUND.md) ·
  [FTO_TODO.md](docs/FTO_TODO.md) · [PRIOR_ART_NOTES.md](docs/PRIOR_ART_NOTES.md)
- ADRs 0001–0013 — crypto suite, TS reference, VRF sortition, quorum receipts, ZK
  policy-satisfaction, govern-the-verb oracle, CNSA 2.0, CBOM, LMS/XMSS code-signing,
  COSE/RATS, SBOM/SLSA, and the v:2 commitment-binding (ADR-0013: structural binding;
  primitive implemented + tested in `disclosure/commitbind.ts`, UNAUDITED): see [docs/adr/](docs/adr/)
- Launch readiness + gate packages: [LAUNCH_READINESS.md](docs/LAUNCH_READINESS.md) ·
  [FTO_PACKAGE.md](docs/FTO_PACKAGE.md) · [AUDIT_PACKAGE.md](docs/AUDIT_PACKAGE.md) ·
  [DEPLOY_HARDWARE.md](docs/DEPLOY_HARDWARE.md) · grant: [docs/grants/](docs/grants/)
- Council verdicts: [docs/council/](docs/council/)

## Principles

Post-quantum all the way down. Govern the verb, never the eye. Decentralize
trust, centralize accountability. Prove everything; reveal nothing unnecessary.
No security theater — if something is only evidence, we label it evidence.

## License

Licensed under the [Apache License, Version 2.0](LICENSE) — see [`NOTICE`](NOTICE)
for attribution and [`third_party/`](third_party/) for the bundled third-party
license texts. Per-file licensing follows the [REUSE](https://reuse.software)
specification (`REUSE.toml` + SPDX headers); run `reuse lint` to verify.

Copyright 2026 TRELYAN.
