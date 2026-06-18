# PolarSeek — STATUS

**Phase: P0–P3 software build complete; conformance ✔.** Updated 2026-06-18.
**137 tests pass** (`npm run gate`). **`npm run conformance` → 11/11 CONFORMANT.**

## Modules — all implemented, tested, and conformance-checked

| Module | What it provides |
|---|---|
| `crypto/` | SuiteID crypto-agility, hybrid KEMs, ML-DSA-87/SLH-DSA, deterministic CBOR, signed envelopes, PermitTokens, KATs |
| `capabilities/` | Typed, attenuation-only (UCAN/macaroon) PQ-signed authority; default-deny resolver; signed-scalar aggregates |
| `kernel/` | Stateless deterministic `decide()`; risk-tiering; byte-identical ReplayBundle; TLA⁺ safety model |
| `receipts/` | PQ receipts (hashes only, no PII); external `verifyReceiptInclusion` |
| `translog/` | RFC 6962 Merkle log (inclusion + consistency); **Signed Tree Heads + split-view detection**; persistent file log |
| `attest/` | RATS attestation (software root real; TEE stubs); N-of-M heterogeneous appraisal |
| `planes/` | `PolarSeekNode` orchestration; **action-bound PermitTokens** (replay-resistant) |
| `governance/` | **M-of-N quorum**, revocation registry, customer local kill switch |
| `disclosure/` | Sound selective disclosure; **ZK range proof** (`amount < threshold`, audited group / unaudited protocol) |
| `sdks/ts/` | `PolarSeekClient` + **MCP/tool-call adapter** (a denied call never executes) |
| `conformance/` | The certification suite — 11 checks across every guarantee |

## Runnable

- `npm run gate` — clean-room lint + prettier + tsc + 137 tests
- `npm run demo` — end-to-end T2 governed payment
- `npm run build && npm run bundle && npm run verify:cli` — independent external receipt verification
- `npm run conformance` — certification report (11/11)

## Deployment maturity — Local/Private dev (honest)

Everything **software can supply** is built and tested. **NOT yet** (and mostly not closable by code):

| Gap | Closes via | Code? |
|---|---|---|
| Patent-counsel **FTO** | counsel | ❌ (FTO_TODO.md) |
| External **security/crypto audit** (incl. the ZK protocol) | audit firm | ❌ |
| Real **TEE** (TDX/SEV-SNP/CCA) + **HSM/KMS** | hardware/cloud | ❌ (stubs in place) |
| **Rust** hot-path (true <1 ms, constant-time) | provision `rustup` + port to the conformance contract | ✅ pending toolchain |
| Machine-checked **TLA⁺**; threshold-MPC (vs M-of-N); P4 PoS **ledger** + public network; Python/Go SDKs | more build | ✅ |

See [DEPLOY.md](./DEPLOY.md). Design-around ≠ legal opinion — FTO required ([FTO_TODO.md](./FTO_TODO.md)).

## Council

P0 council PASS with corrections ([council/P0-verdicts.md](./council/P0-verdicts.md)); the replay finding is addressed (action-bound permits). Re-run the full council + commission the ZK/crypto audit before any external claim or pilot sign-off.
