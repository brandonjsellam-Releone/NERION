# PolarSeek — STATUS

**Phase: P0–P4 software build complete; conformance ✔; Rust foundation compiles.** Updated 2026-06-20.
**469 tests pass** (`npm run gate`). **`npm run conformance` → 23/23 CONFORMANT.**

## Modules — all implemented, tested, and conformance-checked

| Module | What it provides |
|---|---|
| `crypto/` | SuiteID crypto-agility, hybrid KEMs, ML-DSA-87/SLH-DSA, deterministic CBOR, signed envelopes, PermitTokens, KATs; **CNSA 2.0 conformance oracle** (`assessCnsa20` — machine-checkable NSA CNSA 2.0 classification, C15; [ADR-0008](./adr/ADR-0008-cnsa2-oracle.md)) |
| `capabilities/` | Typed, attenuation-only (UCAN/macaroon) PQ-signed authority; default-deny resolver; signed-scalar aggregates |
| `kernel/` | Stateless deterministic `decide()`; risk-tiering; byte-identical ReplayBundle; TLA⁺ safety model |
| `receipts/` | PQ receipts (hashes only, no PII); external `verifyReceiptInclusion`; **decentralized k-of-n quorum receipts** — no single host signs; validator-set-bound ([ADR-0005](./adr/ADR-0005-quorum-receipts.md)) |
| `translog/` | RFC 6962 Merkle log (inclusion + consistency); **Signed Tree Heads + split-view detection**; persistent file log |
| `attest/` | RATS attestation (software root real); **TEE quote-verifier adapter framework** (plug real TDX/SEV-SNP/CCA + measurement policy); N-of-M heterogeneous appraisal |
| `planes/` | `PolarSeekNode` orchestration; **action-bound PermitTokens** (replay-resistant) |
| `governance/` | **M-of-N quorum**, revocation registry, customer local kill switch |
| `disclosure/` | Sound selective disclosure; **ZK range proof** (`amount < threshold`); **ZK Policy-Satisfaction Proof** — prove `amount ≤ ceiling` / `aggregate+amount ≤ cap` revealing NO amount ([ADR-0006](./adr/ADR-0006-zk-policy-satisfaction.md)); audited group / **unaudited protocol** |
| `sdks/ts/` | `PolarSeekClient` + **MCP/tool-call adapter** (a denied call never executes) |
| `ledger/` | **Pure-PoS** ledger: **VRF private sortition + view-change liveness** ([ADR-0004](./adr/ADR-0004-vrf-sortition.md)) over the deprecated canonical-round mode, ≥2/3 stake finality with **equivocation detection + slashing (accountable safety)**, PQ light-client verification |
| `settlement/` | **Non-transferable metering credits** (issuer-signed; meter-down; no transfer op; token deferred) |
| `keystore/` | **Key-custody abstraction**: `KeyProvider` + working software backend + **HSM/KMS provider stubs** (PKCS#11, cloud KMS); keys never leave the provider |
| `conformance/` | The certification suite — **23 checks** across every guarantee, incl. **C14 govern-the-verb negative oracle** (decision invariant to perception-shaped inputs — [ADR-0007](./adr/ADR-0007-govern-the-verb-oracle.md)) |
| `rust/` | **Compiler-verified** Rust hot-path: **full Plane-1 crypto** (HMAC-SHA-384 + AES-256-GCM) + **ML-DSA-87 + ML-KEM-1024** + SuiteID + SHA3 (RustCrypto). **13 tests pass** (9 unit + 4 KAT byte-exact against `conformance/vectors/ps-kat.json`); `gate-rust` CI job runs on every push |

## Runnable

- `npm run gate` — clean-room lint + prettier + tsc + 469 tests
- `npm run demo` — end-to-end T2 governed payment
- `npm run build && npm run bundle && npm run verify:cli` — independent external receipt verification
- `npm run conformance` — certification report (23/23)
- `cd rust && cargo test` — Rust foundation: 13 tests pass (9 unit + 4 KAT); `gate-rust` CI runs on every push

## Deployment maturity — Local/Private dev (honest)

Everything **software can supply** is built and tested. **NOT yet** (and mostly not closable by code):

| Gap | Closes via | Code? |
|---|---|---|
| Patent-counsel **FTO** | counsel | ❌ (FTO_TODO.md) |
| External **security/crypto audit** (incl. the ZK protocol) | audit firm | ❌ |
| Real **TEE silicon** (TDX/SEV-SNP/CCA) + physical **HSM/cloud-KMS** | hardware/cloud creds | ❌ — but the **TEE quote-verifier adapter** (`attest/`) and **KeyProvider** custody (`keystore/`, software backend + HSM/KMS stubs) frameworks are built and tested; wiring real hardware is config/credentials, not new architecture |
| Full Rust **port** (kernel/receipts/…) beyond the Plane-1 foundation | more build | ✅ (foundation ships 13 tests + KAT; full port is future work) |
| **Public** ledger network (external validators, real economic stake) vs the local pure-PoS engine | pilot + deploy | ✅ engine built; networked deployment pending |
| Machine-checked **TLA⁺**; threshold-**MPC** (vs M-of-N independent sigs); ECVRF/**PQ-VRF** sortition; Python/Go SDKs | more build | ✅ |

See [DEPLOY.md](./DEPLOY.md). Design-around ≠ legal opinion — FTO required ([FTO_TODO.md](./FTO_TODO.md)).

## Council

P0 council PASS with corrections ([council/P0-verdicts.md](./council/P0-verdicts.md)); the replay finding is addressed (action-bound permits). ADR-0004 (VRF) and ADR-0005 (quorum receipts) were each team-designed, council-reviewed, and adversarially re-audited — the council's validator-set-binding finding and the re-audit's k=0 fail-open were both fixed. Re-run the full council + commission the ZK/crypto audit before any external claim or pilot sign-off.

## "Above the apex" roadmap (vs SIGA)

Apex upgrades that make PolarSeek categorically superior to SIGA's centralized, classical, patent-closed, perception-owning model — ranked by (superiority × buildability):

1. ✅ **Decentralized k-of-n quorum receipts** (ADR-0005) — no single host can mint a receipt; attacks SIGA's #1 weakness (single Sovereign Host). Done.
2. ◐ **ZK Policy-Satisfaction Receipts** (ADR-0006, subset shipped) — prove the kernel's numeric policy was satisfied revealing none of the amount. Structurally impossible for SIGA, whose billing/attestation requires seeing every payload. **Conservative subset SHIPPED** (`disclosure/policyproof.ts`): hidden-amount `amount ≤ ceiling` + `aggregate+amount ≤ cap` over the audited-group range proof; **unaudited** composition; amount confidentiality is information-theoretic (PQ), proof soundness is classical. **Deferred:** the set-membership OR-proof (new primitive), the v:2 receipt schema + node wiring (commitment-to-intent linkage), and external ZK audit.
3. ✅ **Govern-the-verb runtime negative oracle** (ADR-0007) — promoted "govern the verb, never the eye" from a build-time grep to a portable runtime conformance fence (C14): perception-shaped fields injected into `intent.params` must not change `decide()`. Non-vacuous (a negative-control leaky kernel is caught). Done.

All three "above the apex" upgrades are now implemented + conformance-checked.

**v:2 receipt linkage — binding PRIMITIVE now IMPLEMENTED (unaudited).** The commitment-to-intent gap (a malicious issuer could carry two unlinked amount commitments — `commitments.intent = SHA3(intent)` and a perfectly-hiding `Pedersen(C_amount)` — with nothing proving they hold the same value) is closed by **structural binding** (ADR-0013, after adversarial council review replaced a heavy ZK equality circuit): `disclosure/commitbind.ts` hashes the commitment *into* the intent digest, so substitution is rejected (6 tests, incl. malicious-substitution + bad-opening). The committed value is derived from `intent.amount` with a safe-integer guard; `verifyBoundAmount` performs the full opening check. **UNAUDITED**; full v:2 receipt-body wiring + external ZK audit still pending.

**Top forward upgrade (Team Apex deep audit, 2026-06-20):** migrate the commitment layer from classical Pedersen/ristretto255 to a **post-quantum commitment scheme** (lattice- or hash-based), preserving the v:2 SHA3 binding + re-running C21 — this makes the ZK layer's *soundness* post-quantum end-to-end (today the commitment *hiding* is PQ/information-theoretic, but the proof *soundness* is classical/transitional, discrete-log), and raises the audit bar from a bespoke classical proof to a PQ primitive + binding argument. The proof's zero-knowledge is also only ROM-proven, not QROM-analyzed. See [ASSURANCE.md](./ASSURANCE.md).

## US-gov public-standards track (CNSA 2.0 / NIST / SCITT / Zero-Trust)

Grounding PolarSeek in the authoritative PUBLIC/declassified corpus (no classified material) for gov credibility:

1. ✅ **CNSA 2.0 conformance oracle** (ADR-0008, C15) — machine-checkable NSA CNSA 2.0 classification. PS-5 conformant (transitional); PS-1 not; SLH-DSA/FN-DSA flagged excluded.
1b. ✅ **Signed CNSA 2.0 verdict** (`conformance/cnsa-oracle.ts`, C16) — the gov-grade artifact: an ML-DSA-87-signed, deterministic, transparency-log-anchored, externally-verifiable CNSA verdict (`assertCnsa`/`signCnsaVerdict`/`verifyCnsaVerdict`/`cnsaVerdictLeaf`); deny-by-default allow-set, HARD vs WARN findings, level pure/transitional/non-conformant. (Team-ranked #1 of the gov track.)
2. ✅ **Cryptographic Bill of Materials (CBOM)** (ADR-0009, `conformance/cbom.ts`, C17) — signed, anchored, machine-readable crypto inventory from the suite registry; hybrid KEMs decomposed; flags the quantum-vulnerable legs (P-384/X25519); supports the NSM-10/OMB M-23-02 inventory requirement (a CBOM helps satisfy it; not a mandated format). Accuracy council-corrected (Grok).
3. ◐ **LMS / single-tree XMSS code-signing — SAFE SUBSET** (ADR-0010, C18). `crypto/code-sign.ts` (CodeSigner + single-tree policy + gated `getCodeSigner` stub), `keystore/hbs-state.ts` (one-time-key state manager + reserve-before-sign `HbsKeyProvider`, software store gated dev-only), cnsa oracle now flags HSS/XMSSᴹᵀ multi-tree as non-conformant. **Raw primitive NOT built** (`@noble` has none; SP 800-208 §8.1 = FIPS 140-3 L3+ hardware only; adapter-provided, throws). The software state store is **not** a production signer (restore-from-backup can reuse an OTS index → forgery; only an HSM hardware monotonic counter is reuse-safe).
4. ✅ **COSE_Sign1 + RATS/EAT profile** (ADR-0011, `crypto/cose.ts`, C19) — byte-conformant RFC 9052 COSE_Sign1 over ML-DSA-87 (COSE alg -50, IANA provisional) + a nonce-bound EAT attestation-result. Closes the encoding gap blocking byte-level SCITT/RATS. Standards council-fact-checked (Grok corrected the ML-DSA code-point RFC attribution to IANA-provisional).
5. ✅ **Signed SBOM + SLSA provenance** (ADR-0012, `conformance/supplychain.ts`, C20) — CycloneDX SBOM from the real deps + an in-toto/SLSA Provenance v1 statement, COSE-signed + anchored. EO 14028 / SSDF / SLSA procurement artifact (shapes + PQ signing; full transitive SBOM + SLSA L2/L3 are CI concerns).

## Launch readiness — code-complete, NOT launch-cleared

See **[LAUNCH_READINESS.md](./LAUNCH_READINESS.md)** + the counsel/auditor/vendor-ready packages
([FTO_PACKAGE.md](./FTO_PACKAGE.md), [AUDIT_PACKAGE.md](./AUDIT_PACKAGE.md),
[DEPLOY_HARDWARE.md](./DEPLOY_HARDWARE.md)). Four external gates stand between code-complete and launch —
**none closable by code**: (1) **FTO** patent opinion (counsel), (2) **external crypto/ZK audit**
(audit firm), (3) **FIPS 140-3 L3+ HSM/TEE hardware** (vendor + operator), (4) **FIPS CMVP validation**
(accredited lab). PolarSeek has *prepared* each to accelerate the external party; it has *closed* none,
and must never imply otherwise. Conformant ≠ validated; built ≠ audited; provisioned ≠ in-use;
design-around ≠ legal opinion.

## Consensus caveats (for auditors)

Honest, not-yet-closed limitations of the pure-PoS ledger consensus (`ledger/`). These are
**known and unfixed**; they are recorded here so an auditor sees them stated plainly rather than
having to rediscover them. None is claimed resolved. The first is also tracked in
[ADR-0004](./adr/ADR-0004-vrf-sortition.md) (LEDGER-007); the other two are surfaced here.

1. **View-change cert proves only round `r-1`, not a chain from round 0 — round-skip fairness gap
   (LEDGER-007).** A round-`r` block carries a ≥2/3-stake view-change certificate proving that round
   `r-1` timed out, and nothing more (`verifyFinalized` / `proposeVrf` in `ledger/src/chain.ts` call
   `verifyViewChangeCert` with `block.header.round - 1`; the cert message in `ledger/src/leader.ts`
   binds only `(suite, height, prevHash, round)`). Because no cert *chains* back to round 0, a **≥2/3
   coalition** can publish a single cert for some round `r-1` and jump straight to an arbitrary round
   `r`, re-drawing the VRF leader among themselves. This is a **fairness weakening only** —
   exploitable solely by a quorum that already controls liveness — and **safety is unaffected**: each
   block still needs its own independent 2/3 attestations to finalize. The rigorous fix (a cert chain,
   each cert referencing the prior) is future work; it is **not implemented**.

2. **Validator-set identity / epoch is NOT bound into view-change votes, attestations, or
   equivocation proofs — cross-epoch consent-transfer risk.** The signed messages bind suite, height,
   `prevHash`, and round, but **no validator-set id or epoch number**: `attestMessage` (`chain.ts`),
   `viewChangeMessage` (`leader.ts`), and the `EquivocationProof`/`TimeoutVote` structures
   (`equivocation.ts`, `types.ts`) all omit any set/epoch tag. Consequently a vote or attestation
   produced under one validator-set configuration could be **replayed against a different set** that
   happens to share the same `(height, prevHash, round, suite)` — e.g. across a membership/stake
   rotation — letting consent given under one epoch be transferred to another. Today verification is
   always performed against a caller-supplied `ValidatorSet`, so this is latent rather than
   demonstrated in the single-set test harness; it becomes a live risk under any epoch transition or
   reconfiguration. Binding an explicit set/epoch identifier into every consensus signature is the
   intended fix and is **not yet implemented**.

3. **Equivocation is DETECTED but slashing is NOT enforced end-to-end (LEDGER-006).**
   `ledger/src/equivocation.ts` provides `detectEquivocations` (builds a slashable proof when a
   validator double-signs two distinct blocks at the same height), `verifyEquivocationProof`, and
   `slash` (returns a new set with the offender's stake forfeit). These are sound as **pure helpers
   and are exercised only by tests** — the live ledger path (`Ledger.submit` / `appraise` /
   `verifyFinalized` in `chain.ts`) **never calls them**: it does not gather conflicting attestations,
   build proofs, or apply a slash. So the accountable-safety *evidence* primitive exists, but there is
   **no wired pipeline** from detection to stake forfeiture, no equivocation-report ingress, and no
   persistence of slashing across blocks (`chain.ts` itself notes "Equivocation slashing is deferred
   (LEDGER-006)"). An auditor should read "equivocation detection + slashing" as **detection
   implemented, enforcement deferred**, not as a running slashing protocol. (A related guard,
   LEDGER-EQUIV-001, ensures the detector cannot be abused to slash an honest validator for legitimate
   cross-height attestations.)

These caveats concern **liveness fairness, cross-epoch replay, and enforcement wiring** — not the
core ≥2/3 stake-finality safety property, which is unaffected. They remain open pending the external
crypto/consensus audit and are **not** closable by the claims in the rest of this document.
