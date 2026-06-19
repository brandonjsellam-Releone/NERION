# PolarSeek — STATUS

**Phase: P0–P4 software build complete; conformance ✔; Rust foundation compiles.** Updated 2026-06-18.
**148 tests pass** (`npm run gate`). **`npm run conformance` → 11/11 CONFORMANT.**

## Modules — all implemented, tested, and conformance-checked

| Module | What it provides |
|---|---|
| `crypto/` | SuiteID crypto-agility, hybrid KEMs, ML-DSA-87/SLH-DSA, deterministic CBOR, signed envelopes, PermitTokens, KATs |
| `capabilities/` | Typed, attenuation-only (UCAN/macaroon) PQ-signed authority; default-deny resolver; signed-scalar aggregates |
| `kernel/` | Stateless deterministic `decide()`; risk-tiering; byte-identical ReplayBundle; TLA⁺ safety model |
| `receipts/` | PQ receipts (hashes only, no PII); external `verifyReceiptInclusion` |
| `translog/` | RFC 6962 Merkle log (inclusion + consistency); **Signed Tree Heads + split-view detection**; persistent file log |
| `attest/` | RATS attestation (software root real); **TEE quote-verifier adapter framework** (plug real TDX/SEV-SNP/CCA + measurement policy); N-of-M heterogeneous appraisal |
| `planes/` | `PolarSeekNode` orchestration; **action-bound PermitTokens** (replay-resistant) |
| `governance/` | **M-of-N quorum**, revocation registry, customer local kill switch |
| `disclosure/` | Sound selective disclosure; **ZK range proof** (`amount < threshold`, audited group / unaudited protocol) |
| `sdks/ts/` | `PolarSeekClient` + **MCP/tool-call adapter** (a denied call never executes) |
| `ledger/` | **Pure-PoS** ledger: grind-resistant canonical-round sortition, ≥2/3 stake finality with **equivocation detection + slashing (accountable safety)**, PQ light-client verification |
| `settlement/` | **Non-transferable metering credits** (issuer-signed; meter-down; no transfer op; token deferred) |
| `keystore/` | **Key-custody abstraction**: `KeyProvider` + working software backend + **HSM/KMS provider stubs** (PKCS#11, cloud KMS); keys never leave the provider |
| `conformance/` | The certification suite — 11 checks across every guarantee |
| `rust/` | **Compiler-verified** Rust hot-path: **full Plane-1 crypto** (HMAC-SHA-384 + AES-256-GCM) + **ML-DSA-87 + ML-KEM-1024** + SuiteID + SHA3 (RustCrypto). Builds + type-checks; tests compile (not executed here) |

## Runnable

- `npm run gate` — clean-room lint + prettier + tsc + 148 tests
- `npm run demo` — end-to-end T2 governed payment
- `npm run build && npm run bundle && npm run verify:cli` — independent external receipt verification
- `npm run conformance` — certification report (11/11)
- `cd rust && cargo build && cargo test --no-run` — Rust foundation compiles + type-checks (run `cargo test` on a host that permits executing built binaries)

## Deployment maturity — Local/Private dev (honest)

Everything **software can supply** is built and tested. **NOT yet** (and mostly not closable by code):

| Gap | Closes via | Code? |
|---|---|---|
| Patent-counsel **FTO** | counsel | ❌ (FTO_TODO.md) |
| External **security/crypto audit** (incl. the ZK protocol) | audit firm | ❌ |
| Real **TEE silicon** (TDX/SEV-SNP/CCA) + physical **HSM/cloud-KMS** | hardware/cloud creds | ❌ — but the **TEE quote-verifier adapter** (`attest/`) and **KeyProvider** custody (`keystore/`, software backend + HSM/KMS stubs) frameworks are built and tested; wiring real hardware is config/credentials, not new architecture |
| Executing Rust **tests** + the full Rust **port** (kernel/receipts/…) | a host that permits running built binaries (this sandbox blocks it) + more build | ✅ (foundation: ML-DSA-87 + ML-KEM-1024 compile + type-check here) |
| **Public** ledger network (external validators, real economic stake) vs the local pure-PoS engine | pilot + deploy | ✅ engine built; networked deployment pending |
| Machine-checked **TLA⁺**; threshold-**MPC** (vs M-of-N independent sigs); ECVRF/**PQ-VRF** sortition; Python/Go SDKs | more build | ✅ |

See [DEPLOY.md](./DEPLOY.md). Design-around ≠ legal opinion — FTO required ([FTO_TODO.md](./FTO_TODO.md)).

## Council

P0 council PASS with corrections ([council/P0-verdicts.md](./council/P0-verdicts.md)); the replay finding is addressed (action-bound permits). Re-run the full council + commission the ZK/crypto audit before any external claim or pilot sign-off.
