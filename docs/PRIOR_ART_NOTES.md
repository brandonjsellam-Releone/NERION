# PolarSeek — Prior-Art Notes (Decisions Already Made)

Purpose: capture architecture/product decisions already locked in the existing PolarSeek
analysis so the build stays consistent. Sources are the consolidated report
(`polarseek_report.html`, §-numbers = its `<h1 id="secN">` sections) and the build mandate
(`PolarSeek_ClaudeCode_MegaPrompt.md`, §-numbers = that file's sections). Project-memory
files for the sibling BOREALIS/POLARIS dossier are cited as `[memory:...]`.

---

## 1. Mission & positioning (fixed)
- **Product:** Post-Quant PolarSeek — an apex, **post-quantum-native, decentralized execution-governance protocol for AI/agent *actions***; the open, standards-based alternative to SIGA's patented "Sovereign OS / Commit-Point Gate." (MegaPrompt §1; report §13, §16)
- **One-line promise:** "Let AI agents act — but only within provable, auditable, least-privilege boundaries, with post-quantum, regulator-ready evidence anyone can verify." (MegaPrompt §1; report §28.1)
- **Scope boundary (load-bearing):** PolarSeek governs **actions** (typed tool-calls / API requests / transaction intents) — **never perception** (no camera frames, no image/feature decomposition, no object tracking). This is both the technical thesis and the legal firewall. (MegaPrompt §1, §9; report §13.1, §23)
- **Design philosophy = "invert every axis" of SIGA:** actions not perception; open standards + conformance + formal verification + network effects (not patents); threshold/MPC governance (not one sovereign); NIST PQC by construction; public transparency log; earned adoption via a narrow wedge; threshold revocation + customer-held local kill. (report §13)

## 2. Architecture — three planes (fixed)
- **Plane 1 — Hot Admission:** synchronous, **< 1 ms p50, stateless per decision.** SDK wraps intent (canonical CBOR) → Capability Resolver (typed scopes) → **Admission Kernel** (deterministic allow/deny/transform) → **PermitToken** signed with a **session-key MAC (HMAC-SHA-384)**, bound to a fresh attestation. NO per-action PQ signing, NO network round-trip, NO sequence tracking. (MegaPrompt §3; report §14.1)
- **Plane 2 — Nearline Assurance:** async (~1–10 s), batched PQ. Buffer decisions → build **receipts**, batch-sign with **ML-DSA-87** (Falcon/FN-DSA for compact objects once FIPS 206 + hardened libs exist) → **Merkle-anchor** → append to **SCITT-style transparency log** with inclusion proofs → store the **ReplayBundle**. (MegaPrompt §3; report §14.1)
- **Plane 3 — Offline Settlement & Anchoring:** seconds–minutes. PQ-verifiable **pure-PoS ledger + VRF sortition + Falcon state proofs**; metering-credit settlement; **threshold/MPC governance** (upgrade/revocation); long-term roots via **SLH-DSA / LMS / XMSS** ceremonies. (MegaPrompt §3; report §14.1, §20)
- **Same kernel serves all tiers**; the risk tier decides how much assurance runs synchronously. (report §24)

## 3. Risk tiers (fixed taxonomy — T0–T3)
- **T0 (low):** read / search / draft → Plane 1 only; receipt batched later.
- **T1 (medium):** send email / create infra / write to prod DB → Plane 1 + valid fresh session attestation; receipt within SLA.
- **T2 (high):** move money / rotate keys / delete data / deploy / trade → Plane 1 + **synchronous Plane-2 receipt** + optional human/threshold step-up approval before commit.
- **T3 (critical):** physical actuation / mass export / model-weight export → all planes + **N-of-M heterogeneous attestation** + **dual control** + fresh re-attestation.
- (MegaPrompt §3; report §14.2)

## 4. Cryptographic suite (fixed; "verify against current FIPS before coding")
- **KEM:** hybrid **X25519 + ML-KEM-1024** (FIPS 203).
- **General signatures:** **ML-DSA-87** (FIPS 204).
- **Compact receipts:** **FN-DSA / Falcon-1024** (FIPS 206, **forthcoming/DRAFT**) — **optional, enclave-only, never load-bearing until validated.**
- **Long-term roots:** **SLH-DSA** (FIPS 205) + **LMS/XMSS** (SP 800-208).
- **Symmetric / hot path:** **AES-256-GCM**, **HMAC-SHA-384**, SHA-3/SHAKE.
- **Backup KEM (agility):** **HQC** (code-based; NIST-selected Mar 2025).
- **Target:** **CNSA 2.0 (Cat-5)** parameters as the regulated default (transition ~2030 default → 2033 exclusive — confirm dates at build time).
- **Crypto-agility is mandatory:** every signed/encrypted object carries a negotiable `SuiteID` (COSE/CBOR); no hard-coded single algorithm; a second non-lattice KEM (HQC) must be selectable.
- (MegaPrompt §2, §3.1; report §15)

## 5. Core technical components (fixed)
- **Typed capability model:** typed, parameterized, PQ-signed grants (CBOR/CWT) with per-action ceiling, rolling aggregate cap (enforced via **signed counter**, never kernel tracking), allowed-counterparty refs, step-up predicates, risk tier, TTL, `delegable` flag. **Attenuable only** (UCAN/macaroon-style — narrow, never broaden). (MegaPrompt §3.2; report §16)
- **Deterministic policy kernel:** constrained profile of **OPA/Rego or Cedar**; pinned (hashed) evaluator; no nondeterministic built-ins; no live lookups (external facts passed as a hashed snapshot); canonical CBOR; bounded execution. **Machine-checked spec (TLA+ or Lean)** for decision soundness, receipt-implies-authorization, attenuation-never-amplifies. (MegaPrompt §3.3; report §17)
- **Receipts:** commitments/hashes of intent/capability/policy/evaluator/attestation + jurisdiction + risk tier + timestamp + SuiteID + PQ signature + log inclusion proof. **No payloads, no PII in the log.** Selective disclosure + ZK. Multiple independent mirrorable log operators; clients gossip roots (split-view detection). (MegaPrompt §3.4; report §19)
- **Attestation (RATS):** verifier over **Intel TDX / AMD SEV-SNP / ARM CCA** adapters (+ EU-sovereign TPM option). **Session-scoped:** attest at context establishment, mint short-lived key, re-attest periodically and for T2/T3. **N-of-M heterogeneous** roots for high tiers. (MegaPrompt §3.5; report §18)
- **Settlement + governance:** pure-PoS + VRF + Falcon state proofs; **non-transferable metering credits first** (defer any fungible token pending counsel/MiCA/MTL review). Governance = **threshold M-of-N** across independent operators + rotation + slashing + public proposals + a named **accountable-operator legal entity** (foundation/GmbH). **Customer-held local kill switch**; threshold global revocation; **no single veto.** (MegaPrompt §3.6; report §20)

## 6. Named modules — POLAR-* taxonomy (fixed)
Each module = a **conformance profile** (open spec + reference impl + conformance test suite), not a patent. Earning "PolarSeek-Verified" = passing the suite. (report §21; MegaPrompt §5 `modules/`)
- **POLAR-RUNTIME** — core enforcement (mirrors SIGA OMNI-PRES): action admission, capability resolver, risk-tiering, safe-fallback, rate & spend metering, swarm/multi-agent coordination guards, compute-integrity attestation.
- **POLAR-GATEWAY** — regulated-domain bridges (mirrors OMNI-SGOS): finance/payments, identity & consent (eIDAS/EUDI-aware), airspace/UAV, energy/grid, health (EHDS), customs.
- **POLAR-TRADE** — cross-border & supply chain (mirrors OMNI-RIITES): corridor permits, origin/custody proofs (C2PA-linked), procurement integrity, dispute/arbitration evidence, digital-twin governance.
- **POLAR-HARDEN** — integrity & PQ (mirrors OMNI-AVR-CP): PQ migration & crypto-agility, HNDL defense, AI forensic finality, consensus verification, geo-binding, key-lifecycle/ceremonies.

## 7. Deployment modes (fixed — progressive decentralization)
**Local/Private** (ship the wedge here) → **Consortium/Permissioned** → **Public/Decentralized.** (MegaPrompt §3.7; report §28.2 expansion ladder Land → Expand → Network → Standard)

## 8. Repository layout & languages (fixed)
- Monorepo `polarseek/` with dirs: `crypto/`, `kernel/` (+ `eval/`, `spec/`), `capabilities/`, `receipts/`, `translog/`, `attest/`, `planes/`, `ledger/`, `settlement/`, `governance/`, `sdks/`, `modules/`, `conformance/`, `ops/`, `docs/`. (MegaPrompt §5; report §26.1)
- **Languages:** **Rust** for `crypto/`, `kernel/`, `translog/`, `attest/`; **Go or Rust** for `ledger/`; **TypeScript + Python + Go** SDKs. Use vetted PQC libs (liboqs / pq-crystals / RustCrypto) behind the SuiteID abstraction; **never roll your own primitive.** (MegaPrompt §5)
- **SDK adapters:** MCP, LangChain, LlamaIndex. (MegaPrompt §5, P3; report §26)

## 9. Phased plan P0–P4 (fixed sequence, gates & exits)
- **P0 Foundations** (Wks 0–4): monorepo, CI (lint/test/reproducible build/SLSA), SuiteID registry, `crypto/` hybrid KEM + ML-DSA-87 + SLH-DSA + HQC, KAT tests; docs THREAT_MODEL/CLEANROOM/FTO_TODO + ADR-0001. **Exit:** hybrid KEM + ML-DSA round-trip + KATs green in CI.
- **P1 Kernel & Capabilities** (Wks 4–12): typed capabilities + attenuation + default-deny resolver; stateless deterministic kernel; TLA+/Lean spec; ReplayBundle + canonical CBOR + pinned evaluator hashing. **Exit:** byte-identical replay (identical decision + receipt hash); formal properties pass.
- **P2 Receipts & Attestation** (Wks 10–20): receipts (batch ML-DSA-87, Merkle, selective disclosure + 1 ZK property); SCITT-style log (inclusion + consistency proofs, multi-operator + gossip); RATS verifier (TDX/SEV-SNP/CCA); conformance suite v0; Vanta control tracking begins. **Exit:** external CLI verifies receipt signature + log inclusion with zero trust in issuer.
- **P3 Wedge Product** (Wks 18–32): full plane orchestration + risk-tier routing; SDKs + MCP/LangChain/LlamaIndex adapters; Local/Private mode via `ops/` IaC; `modules/POLAR-RUNTIME` + one `POLAR-GATEWAY`. **Exit:** 3 design-partner pilots live; ≥1 auditor/insurer accepts a PolarSeek receipt as evidence.
- **P4 Network & Settlement** (Mo 8–18): `ledger/` (pure-PoS + VRF + Falcon state proofs, light-client PQ verify); `settlement/` metering credits; `governance/` threshold M-of-N + rotation/slashing/proposals; stand up accountable-operator entity; certification program + mark; Consortium → Public. **Exit:** external validators + independent log operators live; certification mark issued.
- (MegaPrompt §6; report §26)

## 10. Non-negotiable guardrails (enforce in code review)
1. **Patent firewall / clean-room** — design only from open standards (NIST PQC, IETF RATS/SCITT/COSE/CBOR, Confidential Computing). Never implement camera perception, static/dynamic frame decomposition, object-identity continuity across frames, or zone-occupancy. Admission kernel **stateless per decision**; aggregate limits arrive as a **signed counter input**, never kernel tracking. Keep `docs/CLEANROOM.md`; emit `docs/FTO_TODO.md` (human must get patent-counsel FTO opinion before any public non-infringement claim or launch). (MegaPrompt §2.1, §9; report §23)
2. **Post-quantum by construction** — no bare RSA/ECDSA except inside an explicit hybrid construction or eIDAS-compatibility shim. (MegaPrompt §2.2)
3. **Crypto-agility mandatory** — negotiable SuiteID everywhere; HQC selectable. (MegaPrompt §2.3)
4. **Security > features** — default-deny, least privilege, no ambient authority, no secrets in logs, reproducible builds + SLSA provenance. (MegaPrompt §2.4)
5. **Determinism where claimed** — "replayable" = byte-identical re-derivation; pinned evaluator versions; canonical CBOR; explicit time + fact snapshots. (MegaPrompt §2.5)
6. **No security theater** — label evidence-only signals (e.g., geo-location) as evidence; honest THREAT_MODEL with residual risks. (MegaPrompt §2.6; report §22)
7. **Do no harm** — defensive only; no offensive capability, no surveillance of persons, no PII in the public log (commitments/hashes only; ZK for disclosure). (MegaPrompt §2.7)

## 11. Multi-model council = a required, blocking review GATE
- Run an automated council review after **every phase** and before any public claim; **block merge on any unresolved high-severity finding**; record verdicts in `docs/council/`. (MegaPrompt §4; report §32)
- Seat assignment: **Gemini** = technical/crypto/standards verification (catches FIPS/parameter drift); **watsonx** = due-diligence / FTO / regulatory re-scan; **Grok / OpenAI / Mistral / DeepSeek / Hermes** = rotating adversarial review (Mistral owns EU/regulatory); **Perplexity + web search** = standing watch on NIST/IETF/EU + prior-art, re-verify all crypto facts at build time (primary source wins). (MegaPrompt §4)
- **Project-owner directive:** the TRELYAN council must be used as active "top team members," not Claude alone; run independent calls in parallel; Gemini had intermittent outages (fall back to OpenAI for fact-checks). [memory:polaris-ai-council]

## 12. Verified fact corrections to honor (do not regress)
- FIPS 203/204/205 **final Aug 2024**; **FIPS 206 (FN-DSA / Falcon) still DRAFT/forthcoming as of 2026** — keep Falcon optional/enclave-only/non-load-bearing. (report §15; [memory:polaris-quantum-fact-corrections])
- Quantum framing (for any narrative/threat copy): breaking RSA-2048 ≈ **~1M physical qubits** (2025 Google/Gidney), not the older ~20M; the "~100,000 qubits" figure is an aggressive theoretical estimate — label as such. **Q-day ≈ early-to-mid 2030s**; do not conflate with narrow "quantum advantage ~2026" demos. [memory:polaris-quantum-fact-corrections]
- HQC NIST-selected **Mar 2025**; CNSA 2.0 ≈ **2030 default → 2033 exclusive** (confirm at build time). (report §15, §27)

## 13. Definition of Done (every unit)
Compiles; lint/format clean; no `unsafe` without justification; unit + property + (where two impls exist) differential tests, meaningful coverage on `crypto/`/`kernel/`/`receipts/`; public APIs documented; ADR for every non-obvious decision; threat-model entry updated if attack surface changed; reproducible build + SLSA provenance; council gate passed (no open high-severity); conventional-commit message + "why" in PR. Maintain `docs/STATUS.md`; end each phase with a tagged release + a one-paragraph exec update. (MegaPrompt §7, §10)

## 14. GTM / moat commitments (product decisions)
- **Beachhead = the narrowest high-pain actions:** move money / execute trades, change cloud infra, export/delete regulated data, merge code / deploy to prod, access PHI/PII, rotate keys / change access. Buyer = security/platform/compliance owner. (report §28.1)
- **Free OSS core**; Local/Private SDK first; expand via POLAR-GATEWAY verticals; consortium logs → insurer/auditor receipt recognition → **"PolarSeek-Verified" certification mark** as the controlling moat. (report §28.2, §29)
- **Moat without patents:** conformance certification, formally-verified kernel, receipt network effects, standards authorship (RATS/SCITT profiles), PQ-native head start, defensive IP on own novelty (stateless-kernel + nearline-counter receipts; three-plane risk-tiered attestation binding). (report §29; §23.3)
- **Regulatory posture:** EU AI Act (accountable-operator entity, transparency log as Art.12/13 record, third-party conformity), eIDAS 2.0/EUDI hybrid sigs, GDPR/EHDS commitments-only + ZK + EU residency, DORA resilience receipts, MiCA/PSD2/MTL → metering credits first, token only after per-jurisdiction counsel review. (report §27.2)
