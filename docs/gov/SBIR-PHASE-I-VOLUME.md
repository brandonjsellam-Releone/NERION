# SBIR Phase I Technical Volume (DRAFT) — Post-Quantum Execution Governance for Autonomous AI Agent Systems

> ============================================================================
> **DRAFT for internal review — not for submission as-is.**
> **TRELYAN Inc. / Nerion. Prepared 2026-06-26.**
> ============================================================================

**Proposing firm:** TRELYAN Inc. — a United States corporation, 100% owned by Brandon Sellam (U.S. citizen, New York).
**Product / reference implementation:** Nerion — open-source post-quantum execution-governance protocol (Apache-2.0).
**Point of contact:** Brandon Sellam, Founder · brandon.sellam@gmail.com · New York, NY.
**Repository:** github.com/brandonjsellam-Releone/NERION

> This document is an internal working draft assembled by the TRELYAN team from six contributed sections and then passed through a no-overclaim adversarial review. It is **not** a finalized submission. Every capability, alignment, conformance, and benchmark statement is scoped precisely and accompanied by explicit maturity and validation caveats; see **§7 Honest Status & Disclaimers**, which governs the entire volume.

---

## Table of Contents

1. [Identification and Significance of the Problem / Opportunity](#1-identification-and-significance-of-the-problem--opportunity)
2. [Technical Innovation](#2-technical-innovation)
3. [Phase I Technical Objectives](#3-phase-i-technical-objectives)
4. [Phase I Work Plan](#4-phase-i-work-plan)
5. [Related Work, Differentiation, and Commercialization](#5-related-work-differentiation-and-commercialization)
6. [Key Personnel, Facilities, and Eligibility](#6-key-personnel-facilities-and-eligibility)
7. [Honest Status & Disclaimers](#7-honest-status--disclaimers)

---

## 1. Identification and Significance of the Problem / Opportunity

> **DRAFT — for principal-investigator review prior to submission. Not for distribution.**

### 1.1 A Convergent Dual Mandate the DoD Must Satisfy Simultaneously

The Department of Defense is executing two transitions at once, and the interval in which they overlap is the source of the problem this proposal addresses.

The first is the migration to post-quantum cryptography (PQC). NIST finalized the core post-quantum standards in 2024 — FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) — and NSA's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) directs National Security Systems toward these algorithms, with software- and firmware-signing transitions beginning near-term and a stated migration horizon around 2030 for the relevant NSS use cases. (CNSA 2.0 is a broader suite that selects specific quantum-resistant algorithms for NSS use; it is not synonymous with "only the three NIST PQ standards," and exact per-use-case timelines should be verified against current NSA guidance before any external claim.) The driving threat is "harvest now, decrypt later": an adversary records protected traffic today and decrypts it once a cryptographically relevant quantum computer (CRQC) exists.

The second is the operational fielding of autonomous and agentic AI systems — software agents that do not merely classify or recommend but _act_: they invoke tools, issue commands, move funds, dispatch effectors, and reconfigure other systems with reduced human-in-the-loop latency. Across CDAO, the Services, and DARPA programs, the trajectory is toward agent meshes and autonomous collaborative platforms operating at machine speed.

These two transitions are treated as separate programs. They are not separate problems. **The same quantum threat that endangers confidential data endangers the cryptographic authorization of autonomous action** — and the second exposure is, for autonomous weapons-adjacent and command-and-control systems, the more consequential of the two.

### 1.2 The "Harvest Now, Forge Later" Threat to AI-Agent Authorization

The PQC migration discourse is framed almost entirely around _confidentiality_ — protecting data so it cannot be read later. Autonomous AI introduces a distinct and under-addressed exposure framed around _authenticity and authorization_ — protecting the right to act so it cannot be **forged** later.

When an autonomous agent is permitted to perform an action, that permission is, in current architectures, expressed as a classically signed token, credential, or command authorization (RSA / ECDSA / Ed25519). It is important to be precise about the mechanism of the future risk, because a loose statement of it invites a fair objection:

- **Replaying a harvested artifact is not the core threat.** A specific authorization token that was nonce-bound, audience-bound, short-lived, replay-protected, and revocable does not, by itself, grant an adversary future command authority once it has expired or been revoked. Standard freshness, expiration, audience-binding, and revocation controls already blunt naive replay of captured artifacts.
- **The core CRQC-specific threat is the ability to mint _new_, valid authorizations.** What a CRQC changes is the security of the _classical signing keys themselves_. An adversary who has harvested protocol observations and exposed public keys, and who later gains a CRQC, may be able to recover or otherwise defeat a classical private signing key and thereby **forge entirely new agent authorizations** that downstream systems will cryptographically accept as legitimate — including authorizations that are fresh, correctly scoped, and non-expired. This defeats freshness and revocation controls precisely because the adversary can mint authorizations that look new and in-policy.

We refer to this end-state as **"harvest now, forge later."** The harvested material (traffic, observed protocol messages, exposed verification keys) is the _enabler_; the _consequence_ is the post-CRQC ability to issue new, valid actions. Its consequences differ from those of data decryption in two ways that matter to the DoD:

| Dimension                           | "Harvest now, **decrypt** later" (confidentiality) | "Harvest now, **forge** later" (authorization)                                                            |
| ----------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| What the adversary ultimately gains | Read access to past secrets                        | Ability to **mint new** future actions the system will accept as authorized                               |
| Affected asset                      | Data already exfiltrated                           | The live decision-and-execution loop of an autonomous system                                              |
| Failure mode                        | Disclosure                                         | **Unauthorized action** (effector dispatch, ROE violation, command injection)                             |
| Detectability                       | Often invisible                                    | A forged-but-valid signature is, by construction, indistinguishable from a legitimate one to the verifier |

For an autonomous collaborative aircraft acting on signed rules of engagement, or a zero-trust agent mesh acting on signed task orders, an authorization that can be forged post-CRQC is not a privacy issue — it is an **integrity-of-command** issue. Classical signatures on agent authorizations are therefore a latent, harvestable liability the moment the system is fielded, even though the consequence does not manifest until the quantum capability exists.

### 1.3 Each Half of the Existing Toolset Solves Only Half the Problem

Two mature bodies of technology appear, individually, to address this. Neither does _out of the box_, because each is on the wrong side of the gap.

**Post-quantum cryptography (libraries, HSMs, KEMs) provides primitives and infrastructure, not an agent-specific authorization gate.** PQC signature and KEM libraries (e.g., the `@noble/post-quantum` family, liboqs, PQClean), third-party FIPS 140-validated HSMs, and post-quantum KEMs are necessary and excellent at their job: establishing quantum-resistant confidentiality and authenticity for a _connection_ or a _stored object_, and — in the case of signature libraries and HSM signing policy — signing or gating _arbitrary payloads_. To be fair to these tools: a signature library can sign a command payload, and an HSM can be configured to enforce a signing policy. What they do **not** provide as a packaged capability is an **AI-agent-specific, policy-bound, pre-execution authorization gate** that answers "is _this specific autonomous action_, by _this agent_, in _this session_, against _this resource_, presently authorized under a pinned policy — and is that authorization bound to a post-quantum signature?" Assembling that gate from raw primitives is exactly the system-level engineering an autonomous program must otherwise do itself; a PQC-secured TLS tunnel will faithfully and quantum-safely transport a forged or out-of-policy agent command. The primitives are post-quantum; the **decision to act** is left ungoverned.

**Existing AI governance commonly lacks PQC-native cryptographic binding of an agent's specific authorization to act.** AI-agent governance stacks vary: many are observational (prompt/response logging, tool-call telemetry, behavioral monitoring, human review), while more mature stacks add signed policies, attestations, allowlists, and runtime enforcement points. The observational components are valuable for forensics and trust calibration but are **detective, not preventive** and frequently **not cryptographically binding** at the moment of execution. Even governance stacks that _do_ enforce typically bind to classical signatures, and rarely bind an agent's _specific, individual_ authorization-to-act to a **post-quantum** signature evaluated fail-closed at admission. The common, structural shortfall is therefore not "no governance" — it is the absence of _PQC-native, per-action, pre-execution_ binding of the verb.

The gap is structural, and it sits precisely between the two:

| Capability needed for governed autonomous execution under PQC         | PQC libraries / HSMs / KEMs                                                 | AI logging / monitoring         | **Commonly Unmet** |
| --------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------- | ------------------ |
| Quantum-resistant transport & key establishment                       | ✔                                                                           | —                               | —                  |
| Post-quantum **signature on the specific action authorization**       | partial (primitive only; not bound to a per-action decision out of the box) | —                               | **✔ gap**          |
| **Preventive, fail-closed** admission decision on the verb            | —                                                                           | partial (often detective only)  | **✔ gap**          |
| Non-repudiable, transparency-anchored record of _what was authorized_ | —                                                                           | partial (logs often repudiable) | **✔ gap**          |
| Default-deny on ambiguity / verifier failure                          | —                                                                           | —                               | **✔ gap**          |

PQC owns the eye and the pipe. Monitoring largely owns the rear-view mirror. **No standard component, as a packaged capability, cryptographically governs the verb — the act of execution — with post-quantum authorization, at the moment of admission, fail-closed.** That is the unmet need this proposal targets.

### 1.4 Quantifying the Gap for DoD Autonomous Systems

The gap is not merely qualitative; it scales adversely with the precise direction in which DoD autonomy is heading.

- **Surface scales with agent count, not user count.** Human-mediated systems gate action at human decision rate. An autonomous agent mesh issues machine-speed actions continuously; a 10-agent scenario in which each issues actions on the order of 10²–10³ times per minute produces a per-minute count of _executable, authorization-bearing events_ that exceeds the lifetime command volume of many human-operated systems. Every one of those events is a "harvest now, forge later" sample if its authorization is classically signed.
- **The window is open now and closes only post-migration.** Any authorization signed classically and observed today contributes to the harvest that may later enable forgery for the entire service life of the platform once a CRQC exists. For long-lived autonomous platforms, the harvest window is effectively the full fielding horizon — a multi-decade exposure that begins at first deployment, not at CRQC arrival.
- **The latency budget makes naive retrofits non-viable.** Autonomous execution loops cannot tolerate human-scale or even web-scale authorization latency; a per-action governance round-trip must complete in well under a millisecond to avoid degrading the very autonomy it protects. Post-quantum signatures (ML-DSA) are larger and costlier than the classical signatures they replace, so "just sign each action post-quantum" is not free — it must be engineered to a hard, measured latency budget on commodity hardware. Establishing whether that budget is rigorously achievable is the empirical crux of the proposed work (§3, Phase I Technical Objectives).
- **CNSA 2.0 makes algorithm alignment a forward requirement, not optional.** The same NSS systems most likely to field autonomous agents are precisely those bound to CNSA 2.0. A governance layer that is not already algorithm-aligned to FIPS 203/204/205 will require re-engineering inside the migration window rather than being migration-native from the start. (We state this as algorithm _alignment_, not certification; see §7.)

### 1.5 The Opportunity: Post-Quantum Execution Governance

We propose to address this gap with a single migration-native capability: **post-quantum execution governance** — cryptographically authorizing _what an autonomous agent may do_ (the action) with post-quantum signatures, fail-closed, at admission time. The design principle is **"govern the verb, never the eye"**: the system places no constraint on what an agent perceives or generates, only a fail-closed, post-quantum-bound gate on what it is permitted to _execute_. This deliberately keeps the governance layer orthogonal to the model, the data pipeline, and the perception stack, and confines its trusted surface to the act of execution.

**Nerion**, the open-source reference implementation TRELYAN brings to this effort, is _designed to_ realize this principle across three planes that map directly onto the latency, assurance, and accountability tiers a DoD autonomous system requires:

| Plane                       | Function                                                                                                                          | Post-quantum binding (designed for CNSA 2.0 algorithm alignment)                      |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| **P1 — Hot Admission**      | Stateless, deterministic `decide()`; default-deny / fail-closed; short-lived per-action PermitToken; per-(session, audience) keys | AES-256-GCM + HMAC-SHA-384 (FIPS 198-1); key establishment via ML-KEM-1024 (FIPS 203) |
| **P2 — Nearline Assurance** | Signed action receipts; RFC-6962 Merkle transparency log; inclusion + consistency proofs                                          | **ML-DSA-87 (FIPS 204)** action-authorization signatures                              |
| **P3 — Offline Settlement** | Proof-of-stake ledger; _k_-of-_n_ quorum governance; accountable-safety / equivocation-slashing                                   | SLH-DSA-SHAKE-256f (FIPS 205) root signing                                            |

The design intent is that every authorized action is bound to a post-quantum signature an adversary cannot forge even with a CRQC — directly targeting "harvest now, forge later" at the level of the verb — while the algorithm selection (ML-KEM-1024, ML-DSA-87, SLH-DSA-SHAKE-256f, AES-256-GCM, HMAC-SHA-384) is chosen to be **designed for CNSA 2.0 algorithm alignment**, so the governance layer is migration-native rather than a retrofit. These are design properties of a working reference implementation, not validated product guarantees (see §7).

### 1.6 Current Maturity and Honest Posture

The reference implementation is a working artifact at private/local development maturity, not a fielded product. Its present evidence base is: 756 automated tests across 102 files; a 23-of-23 in-repo conformance gate; a Rust hot-path with byte-exact cross-checks against NIST Known-Answer-Test (KAT) vectors; FIPS negative-conformance tests (malformed-input rejection and implicit-rejection behavior); and a TLA⁺ model of the consensus accountable-safety property that is **machine-checked with TLC** (no invariant violation across its reachable states; run in CI), though it remains **a model of an abstraction, not a proof of the implementation**. A local development benchmark baseline (single 16-core windows-gnu machine, `--release`, **not certified and not collected on isolated hardware**) shows an ML-DSA-87 sign of roughly 257 µs median and a composite `decide()`-path of roughly 470 µs median — but **p95/p99 are not yet under 500 µs**, with the ML-DSA signature dominating the tail. Substantiating a rigorous sub-500 µs **p99** governance round-trip on isolated, commodity hardware is therefore stated as a Phase I _objective_, not a present claim.

To preserve the credibility this proposal requires, we state the following limitations plainly. Nerion is **designed for CNSA 2.0 algorithm alignment but is not CMVP/FIPS-140-3 validated**; it is **not externally audited** (audit inquiries have been submitted to OSTIF and the OTF Security Lab); it is **pre-Freedom-to-Operate** with no patent non-infringement claim asserted; and its constructions, while they **use upstream-audited `@noble/post-quantum` primitives, are themselves unaudited compositions — Nerion's own integration and system have NOT undergone external audit.** One honest cryptographic gap is already documented internally: an optional zero-knowledge range-proof component rests on a Pedersen/discrete-log assumption and is **not** post-quantum, and is excluded from the post-quantum authorization core accordingly.

### 1.7 Significance: Dual-Use Relevance

The capability is directly relevant to near-term DoD autonomy and to commercial sectors facing parallel accountability mandates:

- **Defense:** PQC-signed rules-of-engagement compliance for collaborative combat aircraft / loyal-wingman swarms; CDAO-style zero-trust AI-agent mesh authorization; verifiable agent-execution chains for DARPA-class autonomous-execution programs; and authorization integrity for autonomous logistics.
- **Commercial:** cryptographic, non-repudiable AI-agent governance and audit for regulated industries (finance, healthcare, critical infrastructure), supporting EU AI Act and NIST AI Risk Management Framework accountability obligations as agentic systems enter production.

**Eligibility note.** TRELYAN Inc. is a United States corporation wholly (100%) owned by Brandon Sellam, a U.S. citizen resident in New York; the firm maintains U.S. business banking and is completing SAM registration. The reference implementation is released under Apache-2.0. As a small business with no prior federal performance, TRELYAN states its maturity and limitations without overstatement, consistent with the posture above and in §7.

---

## 2. Technical Innovation

> **DRAFT — for principal-investigator review prior to submission.** This section describes the technical approach of Nerion, an open-source post-quantum execution-governance protocol developed by TRELYAN Inc. Cryptographic-suite alignment, conformance, and benchmark statements are scoped precisely below; readers should note the explicit maturity and validation caveats in §2.7 and the volume-wide disclaimers in §7. Throughout this section, capability verbs describe the _design and intent_ of a working but unaudited local reference implementation, not validated or certified product behavior.

### 2.1 The problem: authorizing what an agent _does_, not what it _sees_

Autonomous AI agents increasingly take consequential actions — moving funds, reconfiguring infrastructure, exporting data, issuing commands to physical effectors — on the basis of perceived inputs that an adversary can shape. The prevailing security stack was built to protect _identity, keys, and communications channels_: PKI authenticates principals, third-party FIPS 140-validated HSMs custody keys, TLS protects transport, and policy engines (OPA, Cedar) evaluate authorization rules. Individually, none of these mechanisms ships a _verifiable, pre-execution, post-quantum-bound cryptographic gate on the individual action itself_, and none is designed so that the authorization decision is provably independent of perception-derived data that an adversary may have manipulated.

Two trends make this gap acute for defense applications. First, agentic systems compress the loop between perception and irreversible action, removing the human checkpoint that historically constrained automated decisions. Second, the migration to a cryptographically relevant quantum computer (CRQC) creates the **harvest-now, forge-later** exposure described in §1.2: an adversary who records today's protocol observations and exposed verification keys can, once a CRQC matures and classical signing keys fall, **forge new agent commands** that downstream systems will accept as authentic — defeating freshness and revocation because the forged authorizations are themselves fresh and in-policy. Classical signatures on agent actions are a latent liability with a long shelf life.

Nerion is designed to address this gap directly. Its design principle — **"govern the verb, never the eye"** — is that the system cryptographically authorizes _the typed action an agent intends to perform_ (its type, amount, and counterparty), and that this authorization decision is **invariant to perception-shaped data**. Perception may inform an agent's _proposal_; it must never be able to silently change whether that proposal is _admitted_.

### 2.2 Core thesis: the decision invariant

The central technical claim of Nerion is a falsifiable invariant rather than a slogan. The admission decision function is designed to read only explicitly typed action fields and never the free-form parameter bag where perception-derived side-data could ride along. This is enforced at three levels:

1. **By type.** The decision function's inputs are an enumerated, typed action intent (`type`, `amount`, `counterparty`), a typed capability set, a pinned policy, trusted roots, and an explicit signed scalar for any rolling aggregate. The only free-form surface — `intent.params` — is documented as carrying no perception data and is never read by the decision path.
2. **By build-time lint.** A clean-room linter forbids a catalog of perception primitives (frame decomposition, object-identity continuity, zone occupancy, gait/face vectors, and related terms) from appearing in source.
3. **By a portable runtime conformance oracle.** A negative oracle injects perception-shaped fields — individually and in combination — into the action's free-form parameters and asserts that the resulting decision is **byte-identical** to the baseline. Any divergence is flagged as a "govern-the-eye" leak and fails conformance. In the present test corpus the oracle is demonstrated to be **non-vacuous**: a deliberately leaky control decision function, in which a face vector flips the verdict, is correctly caught and named.

This is intended to make "govern the verb, never the eye" a property that any conforming implementation — including a third-party port — must pass at runtime, rather than an architectural assertion taken on trust. It is a conformance-tested design property of the reference implementation, not an externally validated guarantee.

### 2.3 Pre-execution binding: the authorization gate

In Nerion, **every governed agent action is designed to be bound to a verifiable authorization before it is permitted to execute.** The enforcement point is the SDK/tool-call adapter: a denied decision never reaches the underlying tool, effector, or downstream system. The gate is designed to provide a fail-closed, post-quantum, cryptographically binding check on the verb — meaning that on any exception, malformed input, missing capability, expired or out-of-scope token, policy mismatch, or verifier failure, the decision is `deny` by construction (default-deny / fail-closed), and that the authorizing artifact for an admitted action is bound to a post-quantum signature (ML-DSA-87, FIPS 204). These are design and conformance-test properties of an unaudited reference implementation, not validated product behavior; the fail-closed and binding properties are exercised by the test suite and conformance gate described in §2.6, and remain subject to the external-audit caveat in §2.7 and §7.

The admitted-action path issues a short-lived **PermitToken** scoped to a single (session, audience, action) tuple, derived under per-(session, audience) keys so that a token minted for one audience is not honored by another. Freshness, expiration, audience-binding, and single-use semantics are enforced so that a captured token cannot be replayed outside its narrow scope — and, critically, the _forge-later_ threat is targeted at the root by binding the authorization to a post-quantum signature rather than a classical one (§1.2).

### 2.4 The three planes

Nerion separates concerns across three planes tuned to distinct latency, assurance, and accountability tiers. The same separation appears in §1.5; here it is described in implementation terms.

- **P1 — Hot Admission (microsecond tier).** A stateless, deterministic `decide()` evaluates the typed intent against a pinned policy and capability set and returns `permit` or `deny`. It performs no I/O, holds no mutable state across calls, and is the only component on the synchronous execution path. Symmetric protection uses AES-256-GCM and HMAC-SHA-384; session-key establishment uses ML-KEM-1024 (FIPS 203). Determinism is what makes the decision invariant (§2.2) testable and portable.
- **P2 — Nearline Assurance (millisecond tier).** Each admitted action emits a signed **action receipt** appended to an RFC-6962 Merkle transparency log, yielding inclusion and consistency proofs. Receipts are signed with ML-DSA-87 (FIPS 204). This plane provides the non-repudiable, transparency-anchored record of _what was authorized_ that monitoring-only stacks lack.
- **P3 — Offline Settlement (batch tier).** A proof-of-stake ledger with _k_-of-_n_ quorum governance and accountable-safety / equivocation-slashing settles disputes and anchors long-term roots, signed with SLH-DSA-SHAKE-256f (FIPS 205). A TLA⁺ model of the consensus accountable-safety property is maintained in-repo and **machine-checked with TLC in CI** (no invariant violation across its reachable states); it is a model of an abstraction, not an implementation proof.

### 2.5 Crypto-agility and CNSA 2.0 algorithm alignment

Algorithm identifiers are carried in governance policy, not hard-coded into the decision path, so algorithm rotation is a policy update rather than an architectural change. The selected suite — ML-KEM-1024, ML-DSA-87, SLH-DSA-SHAKE-256f, AES-256-GCM, HMAC-SHA-384 — is **chosen for CNSA 2.0 algorithm alignment**. This is an algorithm-selection alignment claim only: it must **never** be read or restated as "CNSA 2.0 certified," "compliant," "validated," or "NSA-approved" (see §7). One construction is explicitly out of the post-quantum core: an optional zero-knowledge range-proof rests on a Pedersen/discrete-log assumption, is **classical (not post-quantum)**, and is excluded from the post-quantum authorization path accordingly.

### 2.6 Evidence base

The present, in-repo evidence for the design above is: **756 automated tests across 102 files**; a **23-of-23 conformance gate** on the published specification; a **Rust hot-path** with **byte-exact KAT cross-checks against NIST vectors**; **FIPS negative-conformance tests** (malformed-input rejection and implicit-rejection behavior); the **non-vacuous negative oracle** of §2.2; and a **TLA⁺ model** of the consensus accountable-safety property that is **machine-checked with TLC in CI** (no invariant violation; a model of an abstraction, not a proof). The local development benchmark baseline (single 16-core windows-gnu machine, `--release`, **uncertified, not on isolated hardware**) shows an ML-DSA-87 sign of ≈257 µs median and a composite `decide()` path of ≈470 µs median; **p95/p99 are not yet under 500 µs**, with the ML-DSA signature dominating the tail. The sub-500 µs **p99** target is therefore presented as a Phase I objective to be measured rigorously on isolated hardware (§3), not as an established result.

### 2.7 Maturity and validation caveats (section-scoped; see §7 for the volume-wide statement)

Nerion is **designed for CNSA 2.0 algorithm alignment but is not CMVP/FIPS-140-3 validated**; it is **externally unaudited** (inquiries submitted to OSTIF and the OTF Security Lab, not yet contracted); it is **pre-Freedom-to-Operate** with **no patent non-infringement claim asserted**; and it has **no federal past performance**. Its cryptographic constructions **use upstream-audited `@noble/post-quantum` primitives; Nerion's own integration, key management, policy logic, failure modes, and packaging have NOT undergone external audit.** All benchmark figures in this section are an **uncertified local development baseline.**

---

## 3. Phase I Technical Objectives

> **DRAFT.** Phase I is a feasibility study. Its purpose is to convert the design properties of §2 — currently evidenced only by an in-repo test suite and an uncertified local benchmark — into rigorously measured, independently reproducible feasibility evidence. No objective below presumes a result already in hand.

The empirical crux of Phase I is whether post-quantum execution governance can meet a machine-speed autonomy latency budget _while_ remaining fail-closed and algorithm-aligned. The objectives are stated as falsifiable questions with explicit success criteria.

**Objective O1 — Rigorous latency characterization on isolated commodity hardware.**
_Question:_ Can a per-action post-quantum governance round-trip (P1 `decide()` plus ML-DSA-87 authorization signing) achieve a **p99 under 500 µs** on isolated, commodity hardware representative of a deployable edge node?
_Method:_ Re-run the benchmark suite under a controlled methodology — pinned cores, disabled frequency scaling, warm-up discards, ≥10⁶ iterations, reported p50/p95/p99/p999 with confidence intervals — on hardware that is _not_ the developer workstation. Characterize the ML-DSA tail contribution separately.
_Success criterion:_ A documented, reproducible measurement of the p99 (achieved or not), with an honest account of the gap and the dominant cost (presently the ML-DSA signature). A negative result (p99 above 500 µs) is a valid Phase I outcome that informs the mitigation path (O2).

**Objective O2 — Tail-latency mitigation feasibility.**
_Question:_ If the naive per-action ML-DSA signature does not meet the p99 budget, which mitigations (batched/aggregated receipt signing, deferred P2 signing off the synchronous path, hardware acceleration, or pre-computation) recover the budget without weakening the fail-closed or post-quantum properties?
_Success criterion:_ At least one mitigation demonstrated to bring measured p99 within budget while preserving default-deny semantics and post-quantum binding of the authorization — or a documented conclusion that the budget requires a specific hardware class.

**Objective O3 — Fail-closed and decision-invariant assurance under adversarial input.**
_Question:_ Does the gate remain default-deny under a systematically expanded adversarial corpus (malformed intents, perception-shaped side-data injection, expired/cross-audience tokens, partial-failure injection)?
_Success criterion:_ Expansion of the negative oracle and FIPS negative-conformance corpus, with the decision-invariant property (§2.2) holding byte-identically across all injected perception fields, and zero fail-open transitions observed.

**Objective O4 — CMVP / FIPS 140-3 boundary scoping (paper study).**
_Question:_ What is a defensible cryptographic-module boundary for the P1/P2 signing and key-establishment path, and what is the realistic path and cost to a future CMVP submission?
_Success criterion:_ A written module-boundary definition and a CMVP-readiness gap analysis. This is a _scoping_ deliverable; it makes **no** claim of validation.

**Objective O5 — External-audit engagement scoping.**
_Question:_ What audit scope and statement-of-work would let an independent lab (e.g., OSTIF / OTF Security Lab or an equivalent) evaluate Nerion's _own_ integration and composition — not merely the upstream primitives?
_Success criterion:_ A defined audit scope and a documented engagement plan, recognizing that the upstream `@noble/post-quantum` audit does **not** cover Nerion's integration, key management, policy logic, failure modes, or packaging.

---

## 4. Phase I Work Plan

> **DRAFT.** Task breakdown for a standard Phase I period of performance. Effort is concentrated on measurement and assurance, consistent with the feasibility nature of the program and the honest posture of §7.

| Task                                                      | Description                                                                                                                                                 | Maps to objective | Deliverable                                               |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------------------------------------------------------- |
| **T1. Benchmark methodology & isolated-hardware harness** | Stand up a reproducible, isolated-hardware benchmark harness; define methodology (core pinning, governor settings, iteration counts, percentile reporting). | O1                | Published harness + methodology doc                       |
| **T2. Latency characterization**                          | Execute T1 harness; characterize p50–p999 and the ML-DSA tail; document the gap to the 500 µs p99 budget.                                                   | O1                | Measurement report (with negative results stated plainly) |
| **T3. Tail-mitigation prototyping**                       | Prototype and measure batched/deferred signing and other mitigations; verify fail-closed and PQC binding preserved.                                         | O2                | Mitigation feasibility report                             |
| **T4. Adversarial-corpus expansion**                      | Expand negative oracle + FIPS negative-conformance corpus; run decision-invariant and fail-closed assertions.                                               | O3                | Expanded conformance corpus + results                     |
| **T5. CMVP boundary & audit scoping**                     | Author module-boundary definition, CMVP-readiness gap analysis, and an external-audit statement-of-work.                                                    | O4, O5            | Boundary doc + readiness gap analysis + audit SOW         |
| **T6. Phase I final report & Phase II plan**              | Synthesize results; define the Phase II prototype and the path to a representative DoD autonomy use case.                                                   | All               | Final report + Phase II technical plan                    |

**Risk register (representative).**

| Risk                                                  | Likelihood  | Impact | Mitigation                                                                                    |
| ----------------------------------------------------- | ----------- | ------ | --------------------------------------------------------------------------------------------- |
| p99 budget not met by naive signing                   | Medium–High | Medium | O2/T3 mitigation path; a negative result is still a valid feasibility finding                 |
| Isolated-hardware results diverge from local baseline | Medium      | Low    | This is expected and is precisely why O1 exists; the local baseline is explicitly uncertified |
| Audit/CMVP cost exceeds Phase I scope                 | High        | Low    | Phase I scopes, does not execute, CMVP and audit; both are paper studies in T5                |
| Single-key-person dependence (small business)         | Medium      | Medium | Open-source, fully public artifact lowers bus-factor; documentation-first deliverables        |

---

## 5. Related Work, Differentiation, and Commercialization

> **DRAFT.**

### 5.1 Related work and why it does not close the gap

- **PQC libraries / KEM-DEM stacks (liboqs, PQClean, `@noble/post-quantum`):** provide the primitives Nerion consumes; do not provide an agent-specific, policy-bound, pre-execution authorization gate (§1.3).
- **Third-party FIPS 140-validated HSMs and PKI:** custody keys and enforce signing policy on payloads; not packaged as a per-action AI-agent admission gate, and validation status attaches to those third-party modules, not to Nerion.
- **Policy engines (OPA, Cedar):** evaluate authorization rules but are not, by themselves, bound to post-quantum signatures on each action nor designed for the decision-invariant property.
- **AI-governance / observability stacks:** commonly detective rather than preventive, and commonly lack PQC-native binding of an agent's specific authorization to act (§1.3).

Nerion's differentiation is the _combination_: a fail-closed, deterministic, **post-quantum-bound** gate on the verb, evaluated at admission, with a transparency-anchored record — assembled as one capability rather than left as primitives.

### 5.2 Commercialization (dual-use)

- **Defense transition:** PQC-signed rules-of-engagement enforcement for collaborative combat aircraft and loyal-wingman concepts; zero-trust AI-agent mesh authorization; verifiable agent-execution chains for autonomous-execution programs; authorization integrity for autonomous logistics.
- **Commercial:** non-repudiable, cryptographic AI-agent governance for finance, healthcare, and critical infrastructure, supporting NIST AI RMF and EU AI Act accountability obligations.
- **Open-source posture:** Apache-2.0 licensing supports an auditable supply chain, no vendor lock-in, and a path to a standards-track reference implementation rather than a proprietary black box. TRELYAN's commercial model is built around support, integration, assurance/audit packaging, and a validated commercial build — _not_ around restricting the protocol.

---

## 6. Key Personnel, Facilities, and Eligibility

> **DRAFT.**

**Principal Investigator / Founder.** Brandon Sellam, Founder of TRELYAN Inc.; maintainer of the Nerion protocol; U.S. citizen resident in New York. Responsible for protocol design, cryptographic integration, and the conformance and benchmark suites.

**Facilities and resources.** Development is conducted on commodity hardware with a Rust hot-path toolchain and a TypeScript reference layer over the `@noble/post-quantum` primitives. The full artifact is public (Apache-2.0) at github.com/brandonjsellam-Releone/NERION, which lowers bus-factor and supports independent reproduction of all stated test and conformance results. Phase I isolated-hardware benchmarking (O1/T1) will be performed on dedicated, non-developer hardware procured or provisioned for measurement integrity.

**Small-business and ownership eligibility.** TRELYAN Inc. is a United States corporation **100% owned by Brandon Sellam, a U.S. citizen**, satisfying the U.S.-ownership requirement for SBIR eligibility. The firm maintains U.S. business banking (Mercury) and is completing SAM.gov registration (entity registration submitted; UEI forthcoming). No foreign government has ownership, control, or influence over TRELYAN or Nerion. The pending NLnet grant application is for independent European research funding and does not direct product or security decisions.

**Past performance.** No prior federal performance. Comparable technical work is the public protocol specification, the 756-test / 23-of-23-conformance suite, the Rust hot-path with KAT byte-exact cross-checks, and the submitted independent-audit inquiries. TRELYAN states this plainly rather than overstating readiness.

---

## 7. Honest Status & Disclaimers

> **This section governs every claim in this volume. Where any earlier sentence could be read as a stronger assertion, this section controls.**

- **Algorithm alignment, not certification.** Nerion is **designed for CNSA 2.0 algorithm alignment** (ML-KEM-1024 / ML-DSA-87 / SLH-DSA-SHAKE-256f / AES-256-GCM / HMAC-SHA-384). This is an algorithm-selection statement only. It must **never** be restated as "CNSA 2.0 certified," "compliant," "validated," or "NSA-approved." CNSA 2.0 is a broader NSA suite, not a synonym for the three NIST PQ standards, and per-use-case migration timelines should be verified against current NSA guidance before any external claim.
- **Unaudited.** Nerion's **own integration and system have NOT undergone external audit.** It **uses upstream-audited `@noble/post-quantum` primitives**, but that upstream audit does **not** cover Nerion's architecture, integration, key management, policy logic, failure modes, or packaging. Independent-audit inquiries have been **submitted to OSTIF and the OTF Security Lab**; no audit is yet contracted.
- **Not FIPS 140-3 / CMVP validated.** No CMVP process has been completed or initiated for validation. The cryptographic-module boundary is a Phase I scoping deliverable (O4/T5), not a validated module.
- **Pre-Freedom-to-Operate (pre-FTO).** No freedom-to-operate analysis has been completed and **no patent non-infringement claim is asserted.**
- **No federal past performance.** This would be TRELYAN's first federal engagement.
- **Benchmark numbers are an uncertified local development baseline.** All latency figures (e.g., ≈257 µs ML-DSA-87 sign, ≈470 µs composite `decide()` median) were collected on a single 16-core windows-gnu developer machine in `--release`, **not on isolated hardware and not certified**; **p95/p99 are not yet under 500 µs.** Phase I (O1/T2) will produce rigorous, reproducible measurements on isolated hardware, including honest negative results.
- **One known non-PQC component.** The optional zero-knowledge range-proof rests on a Pedersen/discrete-log assumption, is **classical (not post-quantum)**, and is **excluded** from the post-quantum authorization core.
- **Capability statements are design and conformance-test properties of an unaudited reference implementation,** not validated or certified product guarantees.
- **SBIR ownership eligibility is met:** TRELYAN Inc. is a U.S. corporation **100% owned by a U.S. citizen** (Brandon Sellam, New York). SAM.gov registration is in progress (UEI forthcoming).

---

_Prepared 2026-06-26 by the TRELYAN team. DRAFT for internal principal-investigator review — not for submission as-is. TRELYAN Inc. / Nerion. The reference implementation is Apache-2.0. These materials are for research and evaluation; TRELYAN makes no claim of FIPS certification, government approval, or patent non-infringement._
