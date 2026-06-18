# Post-Quant PolarSeek

**An open, post-quantum-native, decentralized execution-governance protocol for
AI/agent _actions_.** PolarSeek lets agents act — but only within provable,
auditable, least-privilege boundaries, with post-quantum, regulator-ready
evidence anyone can verify.

> **Govern the verb, never the eye.** PolarSeek governs typed **actions**
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

## Status — P0–P2 complete + hardened ✅ (Local/Private dev-deployable)

`crypto/`, `capabilities/`, `kernel/`, `receipts/`, `translog/`, `attest/`, and
`planes/` are implemented in TypeScript over audited `@noble` libraries
(ADR-0002), with **108 passing tests**. The kernel is stateless/deterministic,
PermitTokens are action-bound (replay-resistant), and an external CLI verifies a
receipt's signature + transparency-log inclusion with no operator trust.
`ledger/`, `settlement/`, `governance/`, and the `sdks/` agent adapters remain
scaffolding. Deployment maturity is **Local/Private dev** — see
[docs/DEPLOY.md](docs/DEPLOY.md) and [docs/STATUS.md](docs/STATUS.md).

```bash
npm ci
npm run gate          # clean-room lint + prettier + tsc + 108 tests
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

- [STATUS.md](docs/STATUS.md) · [THREAT_MODEL.md](docs/THREAT_MODEL.md) ·
  [CLEANROOM.md](docs/CLEANROOM.md) · [DESIGN_AROUND.md](docs/DESIGN_AROUND.md) ·
  [FTO_TODO.md](docs/FTO_TODO.md) · [PRIOR_ART_NOTES.md](docs/PRIOR_ART_NOTES.md)
- ADRs: [0001 crypto suite](docs/adr/ADR-0001-crypto-suite.md) ·
  [0002 TS reference & KEM pairing](docs/adr/ADR-0002-ts-reference-and-kem-pairing.md) ·
  [0003 repo location](docs/adr/ADR-0003-repo-location.md)
- Council verdicts: [docs/council/](docs/council/)

## Principles

Post-quantum all the way down. Govern the verb, never the eye. Decentralize
trust, centralize accountability. Prove everything; reveal nothing unnecessary.
No security theater — if something is only evidence, we label it evidence.

License: Apache-2.0
