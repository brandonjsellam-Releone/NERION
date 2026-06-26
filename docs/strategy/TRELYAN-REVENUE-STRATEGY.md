<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# TRELYAN Revenue Strategy (DRAFT)

> **TRELYAN Revenue Strategy (DRAFT) — maximizing total revenue on Nerion. Prepared 2026-06-26. Strategy & materials only; no financial action is executed by this document.**

> All dollar figures in this document are **labeled estimates with stated assumptions**, grounded where possible in published program parameters and open-core comparables. They are **NOT bookings, forecasts, guarantees, or commitments.** Nerion is **UNAUDITED, pre-product (Local/Private dev posture), CNSA-2.0-aligned (not certified), pre-FTO, with zero current customers.** Nothing here claims FIPS validation, a completed audit, NSA approval, non-infringement, or existing revenue. No money is moved, no contract is signed, and no raise is executed by this document. Brandon (founder) runs any actual pricing, contracting, fundraising, or financial action.

---

## Executive Summary

### The dual-mandate opportunity

Two government-forced procurement clocks are converging on exactly the slot Nerion occupies:

1. **The post-quantum mandate** — CNSA-2.0's 2030 horizon for national-security systems, the June-2026 quantum executive orders, and the broader "harvest-now-decrypt-later" pressure are forcing regulated and defense buyers to migrate to PQC.
2. **The AI-agent-governance mandate** — the EU AI Act (Art-12/15 logging + robustness), NIST AI RMF, and the operational reality of autonomous agents taking consequential actions are forcing those same buyers to *govern what agents are allowed to do*, with tamper-evident evidence.

Nerion sits at the intersection — **"govern the verb, never the eye"** — binding AI-agent *actions* (not perception, not keys alone) with post-quantum cryptography at execution time. Incumbents (Entrust, Thales, IBM) secure *keys*; Nerion secures *decisions*. For autonomous DoD systems and regulated AI fleets, there is no commercial incumbent in this exact slot. That gap is the entire revenue thesis.

### The 7 streams + investor track at a glance

| # | Stream | Primary motion | Dilutive? | Near-term role |
|---|---|---|---|---|
| **R1** | Open-Core: "Nerion Enterprise" | Open-source-led / PLG-for-infra → paid custody, control plane, SLAs | No (revenue) | The recurring engine (12-24mo build) |
| **R2** | Federal & Defense Contracts | SBIR/STTR ladder, DIU/AFWERX CSO, OTAs, Phase III sole-source | **No (non-dilutive)** | The biggest near-term cash line |
| **R3** | Grants & Non-Dilutive Programs | NLnet/NGI, NSF, civilian R&D, foundation/standards | **No (non-dilutive)** | Keeps the company alive while the build matures |
| **R4** | Managed / Hosted Control Plane (SaaS) | Operated transparency log, key rotation, quorum ops | No (revenue) | Recurring layer on top of R1 |
| **R5** | Custody & Hardware Integration Services | Validated HSM/KMS/TEE bindings, deployment services | No (revenue) | Bridges open seams → paid value; funds the audit |
| **R6** | Support, Training & Certification | Support SLAs, LTS, training, conformance certification | No (revenue) | High-margin attach; standards halo |
| **R7** | Standards, IP & Ecosystem / OEM-Embed | did:nerion, IETF/W3C hooks, OEM/embed licensing | No (revenue) | Long-tail; credibility-to-cash |
| **R8** | Investor Track (raise) | Pre-seed/seed + non-dilutive stacking; STRATFI/TACFI matching | **Yes (dilutive)** | Funds the R1/R4/R5 build — *prepare only* |

### Headline sequencing

**Non-dilutive-first → recurring engine → scale + raise to fund the build.**

1. **Phase 1 (0-15 mo) — Non-dilutive first.** Grants (R3) + Federal/SBIR (R2) are the near-term cash rail. They are non-dilutive, they manufacture the federal past-performance TRELYAN most lacks, and they fund the audit + first live custody binding that everything else gates on. Early paid *pilots/services* (R1/R5 at design-partner pricing) run in parallel but are **not** SaaS ARR yet.
2. **Phase 2 (12-30 mo) — Build the recurring engine.** With audit complete and ≥1 FIPS-listed-HSM custody path live, the open-core paid tiers (R1), managed control plane (R4), custody services (R5), and support/LTS (R6) become credibly sellable. This is where recurring revenue starts — modestly, gated on audit + custody + FTO.
3. **Phase 3 (24-36 mo) — Scale + (optionally) raise.** Enterprise/defense conversions, Phase II/III federal scope, and a deliberate **raise (R8)** to fund the commercial build that non-dilutive money cannot fully cover. The raise is *prepare-only* in this document; Brandon runs it.

The strategy maximizes **total** revenue by stacking non-dilutive money (which costs no equity and builds credibility) *under* a recurring commercial engine, and using a raise only to accelerate the build — not to keep the lights on.

---

## Stream R1 — Open-Core: "Nerion Enterprise"

> *One-line estimate (de-anchored): Open-Core ARR is a 12-24mo build that sits behind grants/SBIR. ~$0 SaaS ARR in Year 1 (design-partner pilots at $0-25k); first real recurring revenue only after audit + a FIPS-listed-HSM custody path land. All ranges below are estimates, not bookings.*

### 1. The thesis: where the open/paid line falls

Nerion's 3-plane architecture *is* the open-core boundary, drawn along the line operators cannot self-serve:

| Plane | What it is | Open (Apache-2.0) | Paid (Nerion Enterprise) |
|---|---|---|---|
| **1 — Hot Admission** | Stateless kernel → PermitToken | Full kernel, clean-room lint, PermitToken logic, Rust hot-path **source** | Pre-built/optimized **hardened Rust binaries** + perf SLA, supported container images |
| **2 — Nearline Assurance** | ML-DSA-87 receipts → Merkle → transparency log | Full receipt + transparency-log spec & reference impl, CLI verifier | **Managed control plane**: hosted/operated transparency log, key rotation, monitoring, compliance export |
| **3 — Offline Settlement** | PoS ledger, threshold/MPC governance, long-term roots | Reference ledger + governance code | **Managed quorum operations**, threshold-key ceremonies, LTS roots |
| **Custody / Attestation** | HSM/KMS/TEE adapter *seams* (built, fake-tested) | The **seams** (interfaces) are open | **The validated bindings** (`Pkcs11WrapEngine`, `HbsSignEngine`, `QuoteVerifier`) wired to real silicon/cloud KMS — the work the DEPLOY_HARDWARE runbook says the operator otherwise writes themselves |

**Governing principle — "the protocol is free; running it safely in a regulated shop is paid."** The boundary maps to a real, documented gap: per `docs/DEPLOY_HARDWARE.md`, the custody/attestation adapter seams ship in the open core but are "net-new code the operator must write AND validate against their specific hardware." Enterprise sells *that* validated, supported, never-write-it-yourself work — not a crippled core.

### 2. What is FREE forever (drives adoption, never alienates)

The entire **protocol, spec, reference implementation, conformance suite, CLI verifier, and clean-room lint** stay Apache-2.0 and feature-complete for self-hosting:

- All crypto suites (ML-KEM-1024 / ML-DSA-87 / SLH-DSA / AES-256-GCM / HMAC-SHA-384), kernel, receipts, transparency log, ledger, governance, ZK disclosure, conformance.
- Rust hot-path **source** + the ability to build it yourself.
- Single-node and self-operated multi-node deployment, software-custodied keys (dev-grade), independent receipt verification with **no operator trust** — that trustless-verification property is a community guarantee and must never move behind the paywall (it is the whole credibility story).
- SDKs, did:nerion method, standards docs.

**Anti-alienation guardrails (the open-core failure mode to avoid — cf. community backlash at companies that relicensed):**

1. Never paywall a security fix or a CVE patch for the core.
2. Never paywall *verifiability* — anyone can always independently verify a receipt for free.
3. No "open-core bait-and-switch": features that ship open stay open (no relicensing of existing core capability). New *operational* surface area can be Enterprise; existing *protocol* surface cannot.
4. Permissive (Apache-2.0), not a source-available/BSL trap — protects the federal/standards/grant positioning (NLnet/NGI explicitly fund *open* commons).

### 3. What is PAID — "Nerion Enterprise" edition

Five value buckets, each tied to a real cost the buyer wants to outsource:

1. **Hardened custody & key management** — validated `Pkcs11WrapEngine` / `HbsSignEngine` / `QuoteVerifier` bindings to FIPS-listed HSMs (Thales Luna 7, Entrust nShield 5, AWS CloudHSM) and cloud KMS, with the hardware-counter state store HBS safety requires. One cloud-KMS sealing seam (Azure Key Vault, RSA-4096 KEK) has been internally round-trip-tested in our own tenant as a **proof-of-seam only** — NOT a customer deployment, NOT a validated HSM custody path, and Azure KV provides no PQC (sealing KEK only). *Sold as "custody that works on real silicon," not "we wrote a wrapper."*
2. **Managed control plane** — hosted/operated transparency log, key rotation, quorum/threshold ceremonies, monitoring, dashboards, multi-tenant governance.
3. **Hardened Rust hot-path** — pre-built, perf-tuned, signed binaries + SBOM/SLSA provenance, with a stated p50/p99 admission-latency SLA.
4. **Compliance reporting** — auto-generated, regulator-ready evidence packs mapped to CNSA-2.0 migration, NIST AI RMF, EU AI Act Art-12/15 logging/robustness, SOC 2 control mappings; signed CycloneDX CBOM exports. *(Alignment artifacts, not certifications — copy stays "supports your audit," never "certified.")*
5. **Support tier: SLAs, priority support, LTS** — security-patch SLA, named support, a multi-year **LTS** branch (the maintained-old-version promise regulated buyers pay for), private security advisories.

### 4. Tiered pricing (annual, USD) — grounded in open-core comparables

**Comparable anchors (published list/benchmark pricing):** GitLab Premium ≈ $29/user/mo (~$348/user/yr) and Ultimate ≈ $99/user/mo; HashiCorp/Vault and GitLab land most mid-market self-managed deals in the **$15k-$80k/yr** band, with enterprise/regulated multi-cluster deals **$100k-$500k+**; infra/security open-core (Grafana, Elastic, Confluent) cluster the same way — Team low-five-figures, Enterprise low-to-mid six figures. Security/compliance posture commands a premium over generic devtools. Nerion prices *per governed control-plane / per protected agent-fleet*, **not per seat** (seats do not reflect value for an infrastructure protocol).

| Tier | Annual range | Unit / who it's for | What's included |
|---|---|---|---|
| **Team** | **$12k-$30k/yr** | One control plane, one environment; a single team putting governed agents into a regulated workflow | Hardened Rust binaries, managed transparency log (single-tenant SaaS or supported self-host), business-hours support, standard compliance export |
| **Business** | **$40k-$120k/yr** | Multi-team / multi-env; regulated enterprise division | Adds HSM/KMS custody bindings (one HSM family), priority support + SLA, full compliance-evidence packs, LTS access, 99.9% control-plane SLA |
| **Enterprise** | **$150k-$500k+/yr** | Bank / health system / critical-infra / defense prime; mission-critical agent fleets | Adds multi-HSM + air-gap/on-prem deploy, dedicated support + named TAM, custom SLAs, threshold/quorum ceremony operations, private advisories, optional FedRAMP/IL-track support once available |

**Modeling assumptions (label every number an estimate):**

- ASP assumed **~$60k blended** across the book once Business is the center of gravity — *an assumption, not an observed average.*
- Sales cycle in regulated/defense: **6-12 months** (long; gates ARR ramp).
- These ranges assume an **audit is complete and at least one HSM custody path is live** before Business/Enterprise are credibly sellable. Pre-audit, only Team-tier "design-partner pilots" are honest to sell.

### 5. Target buyers

- **Federal / defense** (DoD autonomous-systems programs, primes): buy via SBIR/contract first (R2), then Enterprise. Enterprise is the post-pilot commercial landing.
- **Regulated enterprises** deploying AI agents — finance, health, critical-infra — facing the dual PQC + AI-governance mandate. **Primary commercial ICP.**
- **AI-platform vendors / agent-framework companies** who want to OEM/embed governed-execution evidence — partner/embed motion (R7, later).

### 6. GTM motion

- **Open-source-led / PLG-for-infra**: GitHub adoption + conformance + standards (IETF draft, did:nerion, W3C-VC / eIDAS-2 hook) build the credibility funnel; downloads/forks/conformance-runs are the top-of-funnel signal.
- **Design-partner program first**: 2-4 named pilots (ideally one regulated-enterprise + one defense-adjacent) at **$0-$25k** "pilot/services" pricing — explicitly *pre-audit, pre-FTO*, scoped as co-development. These produce the case studies and the custody-on-real-silicon proof.
- **Land via compliance pain, expand via custody/SLA**: enter on "regulator-ready evidence for your agents," expand into HSM custody + managed control plane + LTS.
- **Standards + grant halo as air cover** (NLnet/NGI, NCCoE, QED-C) — credibility, not direct revenue.
- **Founder-led sales** through the entire near-term; no sales hire until repeatable Business-tier deals exist.

### 7. Realistic timeline (solo-founder, pre-product, pre-audit)

| Horizon | State | Open-Core revenue (estimate) |
|---|---|---|
| **0-12 mo** | Non-dilutive primary: NLnet ~€45k (call ~Sept 2026) + SBIR Phase I (agency-dependent). Audit in progress (OSTIF/OTF inquiries submitted). 1-3 design-partner pilots. | **~$0-$50k** (pilots/services, not SaaS ARR) |
| **12-24 mo** | Audit complete (assumption), ≥1 HSM custody path live, FTO opinion on file (gates any non-infringement claim), Team/Business sellable. | **$0-$200k ARR** (estimate; 1-3 paying orgs at most). First SaaS/Enterprise ARR may realistically be **~$0 until month 24-30** per comparable open-core security ramps. The **3-8-org / blended-$60k** scenario is an *upside case* contingent on audit+HSM+FTO all landing early in the window AND ≥1 design-partner pilot already converting. |
| **24-36 mo** | FIPS-custody + LTS mature; Enterprise/defense conversions; possible first sales hire. | **Directional only, NOT a forecast:** IF audit + at least one FIPS-listed HSM custody path + an FTO opinion all land AND 2-4 Enterprise logos convert, a **low-seven-figure ARR run-rate becomes conceivable** — but this is the most speculative cell in the model and is gated on three independent, currently-unsatisfied events. Treat as a **ceiling scenario, not a plan.** *Note: no comparable solo open-core security company reaches this band inside 36 months from a pre-audit start; we are aware of no counterexample and do not assume we will be one.* |

**Staging logic:** near-term real money is **non-dilutive (grants + SBIR) + early paid pilots/services**; Enterprise/SaaS ARR is the 12-24 mo build that a raise funds. No hockey-stick is claimed — the ramp is explicitly gated on audit, custody, and FTO.

### 8. Risks (and why the model is honest about them)

1. **Audit gate** — without a completed independent audit, Business/Enterprise tiers are not credibly sellable to regulated buyers; only Team-tier design pilots are honest. *Mitigation: pilots fund and de-risk the audit; OSTIF/OTF inquiries already out.*
2. **FTO gate** — no non-infringement claim or aggressive "vs. the patented Commit-Point Gate" positioning until counsel FTO is on file. Sales copy must stay on "govern the verb" capability, not legal claims.
3. **Custody-on-real-silicon risk** — the seams are fake-tested only; the first live HSM/TEE binding is real engineering, not config. *Mitigation: one cloud-KMS sealing seam (Azure Key Vault, RSA-4096 KEK) has been internally round-trip-tested in our own tenant as a proof-of-seam only — NOT a customer deployment, NOT a validated HSM custody path (Azure KV provides no PQC; sealing KEK only). The first real HSM binding still runs via a design partner's hardware.*
4. **Open-core community risk** — paywalling the wrong thing kills the adoption funnel that *is* the GTM. Guardrails in §2 are load-bearing.
5. **Solo-founder concentration / long regulated sales cycles** — 6-12 mo cycles + one founder cap near-term throughput; the grant/SBIR rail is what keeps the company alive while the commercial build matures.
6. **FIPS not yet validated** — Enterprise's custody value is "FIPS-listed HSM-backed," and copy must never imply Nerion itself is FIPS-validated; that is the HSM's certificate, not Nerion's.

---

## Stream R2 — Federal & Defense Contracts

> **One-line estimate (revised):** ~**$50K-$275K non-dilutive obligated in 0-15 months** (1-2 SBIR Phase I / CSO feasibility awards, base case; 3 awards is an upside tail, not base) → realistic first-time-awardee Phase II ~**$750k-$1.2M** in 12-30 months if a Phase I converts → **uncapped Phase III sole-source** thereafter. **Probability-weighted 12-mo EV ≈ $30k-$120k** (estimate). All figures are estimates with stated assumptions, not bookings.

This is the **single biggest near-term non-dilutive line** for a solo-founder, pre-product, pre-audit company. It is non-dilutive (no equity given up), it manufactures the one thing TRELYAN most lacks — **federal past performance** — and the June-2026 quantum EOs + CNSA-2.0 2030 horizon have opened the procurement window precisely on Nerion's dual mandate (PQC + AI-agent governance).

### 1. The offer

Three distinct sellable units, sequenced by maturity. We do **not** sell "a product" yet — we sell **funded R&D, feasibility studies, and reference implementations**, which is exactly what a pre-FIPS, unaudited reference implementation is allowed to sell to the government.

| # | Offer | What the government buys | Vehicle | Honest framing |
|---|---|---|---|---|
| **O1** | **Feasibility study** — "PQC governance of autonomous AI agents" | A 3-6 mo study + working prototype demonstrating ML-KEM-1024 / ML-DSA-87 binding of agent actions | SBIR/STTR Phase I; DIU/AFWERX CSO | Research phase; CNSA-2.0 **aligned**, not FIPS-certified |
| **O2** | **Prototype / pilot integration** | A ~24-mo build hardening Nerion into a specific DoD AI program (e.g. CCA/loyal-wingman RoE, zero-trust agent mesh) + a path to FIPS-140-3 CMVP | SBIR Phase II; OTA prototype; STRATFI/TACFI matching | Evaluation-and-development deployment; CMVP process initiated in-phase |
| **O3** | **Sole-source production / sustainment** | Fielded governance fabric + support, once audited + (ideally) FIPS-validated | SBIR **Phase III** (sole-source, uncapped); prime subcontract; GSA Schedule | Only after audit + validation; today this is a **future** line, not a claim |

The wedge that nobody else occupies: **"govern the verb, never the eye."** Entrust/Thales/IBM secure *keys*; Nerion secures *agent decisions* with PQC at execution time. For DoD specifically — autonomous CCA/swarm RoE that a quantum adversary cannot forge — there is no commercial incumbent in this exact slot. That is the proposal's whole reason to win.

### 2. Pricing & economics (ranges + assumptions)

All figures are **published program parameters** for the FY24-FY26 window (SBA SBIR policy directive soft caps; AFWERX/DoD-component practice). Actual award amounts are set by the solicitation, not by us.

#### SBIR/STTR ladder (the spine of this stream)

| Phase | Typical size (USD) | Duration | Basis / comparable | Notes |
|---|---|---|---|---|
| **Phase I** | **$50K-$150K** typical; AFWERX Open-Topic often a **fixed ~$50K** (~3 mo); component topics $100K-$250K (~6 mo) | ~3-9 mo | SBA Phase I soft cap ~**$314K** (FY24, inflation-adjusted; hard cap ~2× w/ waiver) | Fixed-price. Feasibility + prototype. **This is the first federal past-performance record.** |
| **Phase II** | Published soft cap ~**$2.0M** (SBA); AFWERX deals commonly **$1.0M-$1.8M** for established performers. For a **FIRST-TIME solo awardee** the realistic **modal** Phase II is ~**$750k-$1.2M** (estimate). The ceiling is the published cap, **not our forecast.** | ~24 mo | SBA Phase II soft cap ~$2.0M | **Only open to Phase I awardees** (or Direct-to-Phase-II for tech that already has Phase-I-equivalent maturity). |
| **STRATFI / TACFI** (AFWERX matching) | **TACFI** ~$0.5M-$2M; **STRATFI** can stack to **$3M-$15M** total w/ private + gov match | overlay on Phase II | AFWERX published ranges | **PREPARE-ONLY / GATED:** STRATFI/TACFI requires private-capital and/or program-office matching — it ties this stream to the **investor track (R8)** and to a prime/program sponsor. No matching commitment is solicited or accepted by this document; Brandon runs any capital or matching arrangement. |
| **Phase III** | **Uncapped; no SBIR funds**; derivative scope | n/a | SBA Phase III sole-source authority (15 U.S.C. §638) | Agency may **sole-source** without re-competition because the work derives from Phases I/II. This is where real revenue lives — but it is downstream of audit + a satisfied customer. |

**Stated assumptions behind the headline estimate:**

1. **Apply to ~3-5 Phase I / CSO topics** in the first 12 months (AFWERX Open Topic + 1-2 component topics + DIU CSO + 1 civilian, e.g. DHS S&T / CISA-adjacent).
2. **Per-topic win probability is an assumption, not a given: ~10-15%** for a first-time small business with strong technical fit but **no past performance and no audit** — toward the low end on classified/production-leaning topics, slightly higher on Open-Topic/dual-use feasibility. AFWERX Open Topic historically selects a larger volume than narrow component topics, which is why it is the lead.
3. **Expected Phase I awards in year 1: 0-2** (modal outcome **1**). At $50K-$150K each → ~$50K-$275K; 3 awards is an **upside tail, not base.**
4. **Phase I→Phase II conversion ~40-50%** for awardees who execute Phase I cleanly (DoD-wide historical band). So a Phase II is realistically a **12-30 month** event, contingent on landing and delivering a Phase I first.
5. **Probability-weighted 12-mo EV ≈ $30k-$120k** (estimate; e.g. 4 shots × ~10-15% × ~$75k-$150k). Council range was $30k-$80k; we carry **$30k-$120k** to span both views. This is **expected value, NOT a booking**, and the cash may land in **months 9-15** rather than 0-12 given award + obligation lag.
6. **Award ≠ cash-in-hand.** Obligation and first disbursement commonly **lag selection by 1-3+ months**, so the non-dilutive line is best treated as a **0-15-month** (not strictly 0-12-month) event.

#### OTAs / DIU CSO (parallel, non-SBIR path)

- **DIU prototype OTAs** and component CSOs (Commercial Solutions Openings) are a parallel, non-SBIR route to a funded prototype, often faster than the SBIR cycle and sized per-solicitation. Treated as **additional shots on goal**, folded into the 3-5-topics assumption above, not as an independent guaranteed line.

### 3. Sequencing & dependencies

- **0-15 mo:** apply broadly (Open Topic-led); land 0-2 Phase I; deliver cleanly to build past performance. Cash may arrive months 9-15.
- **12-30 mo:** convert a Phase I → Phase II (~$750k-$1.2M modal, first-timer); initiate CMVP in-phase; line up a prime/program sponsor for any STRATFI/TACFI matching (gated on R8).
- **24 mo+:** Phase III sole-source only after audit + a satisfied customer; this is the uncapped tail, downstream of everything above.

### 4. Honest constraints

- **SBIR >51%-US-ownership test is still open** (founder residency) — this is a live eligibility question that must be resolved with counsel before/at application; it is not assumed resolved here.
- **No past performance, no audit** today — the per-shot win probability assumption (10-15%) already prices this in.
- **CNSA-2.0 aligned, not FIPS-certified** — every proposal must say "aligned," never "certified/validated."

---

## Stream R3 — Grants & Non-Dilutive Programs

> *Estimate: stacks with R2 as the near-term non-dilutive rail. Lead line: NLnet ~€45k (Restack call ~Sept 2026, currently paused). Additional civilian R&D + foundation/standards grants as fit. All non-dilutive; all estimates, not awards-in-hand.*

### 1. The role

Grants are the **company's life support while the commercial build matures** and the **credibility halo** that de-risks every other stream. They cost no equity and explicitly fund *open* commons — which is why Nerion's permissive (Apache-2.0) posture is load-bearing for eligibility.

### 2. The pipeline

| Program | Size (estimate) | Status | Fit / notes |
|---|---|---|---|
| **NLnet / NGI (e.g. Restack)** | ~**€45k** (€50k-cap, bundled audit) | **Primary; call opens ≈Sept 2026** (paused now). Repo published + 2 audit threads submitted (OSTIF + OTF Security Lab). Maintainer French + EU clears the EU-nexus knock-out. | Funds open development + a bundled audit — directly de-risks R1's audit gate. |
| **Civilian federal R&D** (NSF, DHS S&T/CISA-adjacent, DOE) | per-program | Prospect | PQC + critical-infra + AI-governance themes; non-dilutive; complements DoD SBIR (R2). |
| **Foundation / standards programs** (NCCoE, QED-C-adjacent, OTF) | small-to-mid | Prospect / in-progress | Credibility + audit + standards convening; OTF Security Lab inquiry already submitted. |

### 3. Assumptions & honesty

- **EU-nexus / EU-substance** is the knock-out for NLnet; the maintainer's French origin + EU residency clears the personal test, but EU substance for the *entity* must be shored up — an open item, not a solved one.
- Grant timing is **out of our control** (Restack opens ~Sept 2026); near-term grant cash is therefore **not guaranteed within 0-12 mo**.
- No grant is awarded by this document; these are **prospects and one in-progress primary**, not bookings.

---

## Stream R4 — Managed / Hosted Control Plane (SaaS)

> *Estimate: the recurring layer that sits on top of R1's open core; first meaningful ARR is the same 12-24mo, audit-gated event as R1. Ranges are estimates, not bookings.*

### 1. The offer

The open core lets anyone *self-operate* the transparency log, key rotation, and quorum ceremonies. **R4 sells operating it for them**: a hosted/managed control plane so a regulated buyer never runs the assurance plane themselves.

- Hosted, monitored **transparency log** (Plane 2) with uptime SLA.
- **Key rotation** and **threshold/quorum ceremony** operations (Plane 3) run as a managed service.
- Dashboards, alerting, multi-tenant governance, compliance-evidence export.

### 2. Pricing model

Priced **per governed control-plane / protected agent-fleet**, folded into the R1 Business/Enterprise tiers (the managed control plane is the "Business+" value). Standalone managed-log SaaS can also be offered at the **Team tier ($12k-$30k/yr)** for buyers who want only the hosted log.

### 3. Why it is honest

- **Verifiability stays free** — even an R4 customer's receipts are independently verifiable by anyone at no cost (the §2 R1 guardrail). R4 sells *operation*, never *verification*.
- First real ARR is **audit-gated** and **~$0 until ~month 24-30** per comparable ramps — same realism as R1.

---

## Stream R5 — Custody & Hardware Integration Services

> *Estimate: project/services revenue that bridges the open seams to paid value and funds the audit; near-term this is the most honest "real money" commercial line (alongside pilots), because it is services, not a product claim. Estimates, not bookings.*

### 1. The offer

`docs/DEPLOY_HARDWARE.md` is explicit: the custody/attestation adapter seams ship open but are "net-new code the operator must write AND validate against their specific hardware." **R5 is TRELYAN doing that work as a paid engagement:**

- Wiring `Pkcs11WrapEngine` / `HbsSignEngine` / `QuoteVerifier` to a customer's **FIPS-listed HSM** (Thales Luna 7, Entrust nShield 5, AWS CloudHSM) or cloud KMS.
- Standing up the hardware-counter state store HBS safety requires.
- Deployment, integration, and validation services toward a hardware-rooted posture.

### 2. Pricing model

- **Design-partner pilots:** **$0-$25k**, scoped as co-development, explicitly *pre-audit, pre-FTO*. These produce the first **custody-on-real-silicon** proof and the case studies R1 needs.
- **Standalone integration engagements:** project-priced; later attach to a Business/Enterprise (R1) subscription + support (R6).

### 3. Honesty

- The seams are **fake-tested only** today; the first live HSM/TEE binding is real engineering, not config.
- **One cloud-KMS sealing seam (Azure Key Vault, RSA-4096 KEK) has been internally round-trip-tested in our own tenant as a proof-of-seam only — NOT a customer deployment, NOT a validated HSM custody path, and Azure KV provides no PQC (sealing KEK only).** The first real HSM binding runs via a design partner's hardware.
- R5 revenue is what **funds and de-risks the audit** that R1/R4 gate on — which is why it leads the commercial sequence even though it is services, not ARR.

---

## Stream R6 — Support, Training & Certification

> *Estimate: high-margin attach revenue layered on R1/R4/R5 once they are sellable; modest standalone training/certification revenue earlier via the standards halo. Estimates, not bookings.*

### 1. The offer

- **Support SLAs + LTS:** security-patch SLA, named support, a multi-year **LTS branch** (the maintained-old-version promise regulated buyers pay for), private security advisories. Attaches to every paid R1 tier.
- **Training:** operator and developer training for self-hosting teams (can sell *before* full Enterprise readiness, since it monetizes the open core's adoption).
- **Conformance certification:** a paid "Nerion-conformant" certification program against the open conformance suite — for vendors who embed Nerion and want to advertise conformance (ties to R7).

### 2. Why it is honest

- Training and conformance certification monetize **adoption and the open conformance suite**, not a product claim — so they are sellable **earlier** than audit-gated ARR.
- Support/LTS pricing is an **attach**, never a paywall on security fixes for the open core (R1 §2 guardrail #1 is absolute).

---

## Stream R7 — Standards, IP & Ecosystem / OEM-Embed

> *Estimate: the long-tail, credibility-to-cash stream; near-zero near-term revenue, meaningful optionality later. Estimates, not bookings; all IP positioning is pre-FTO.*

### 1. The offer

- **did:nerion method + IETF/W3C-VC / eIDAS-2 hooks:** standards positioning that builds the credibility funnel (mostly non-revenue, but strategically load-bearing).
- **OEM / embed licensing:** AI-platform and agent-framework vendors embed Nerion's governed-execution evidence; a partner/embed motion with licensing or revenue-share later.
- **IP:** defensive posture only until FTO is on file. **No offensive IP claim, no "vs. the patented Commit-Point Gate" positioning, and no non-infringement assertion until counsel FTO is in hand.**

### 2. Honesty

- This is **optionality, not a near-term line** — revenue here is years out and contingent on adoption + standards traction.
- All IP/standards copy stays on **capability** ("govern the verb"), never on legal claims, until FTO.

---

## Investor Track (R8) — Raise to Fund the Build

> **PREPARE ONLY — Brandon runs any raise; nothing here executes a transaction.** See the companion outline: `docs/strategy/INVESTOR-DOSSIER-OUTLINE.md`.

### 1. The role

A raise is **not** life support — that is what the non-dilutive rail (R2 + R3) is for. The raise exists to **accelerate the commercial build** (R1 hardened binaries + R4 managed control plane + R5 custody validation + the audit) that non-dilutive money cannot fully cover, and to unlock **STRATFI/TACFI matching** (which requires private capital and/or a program-office sponsor).

### 2. Prepare-only guardrails

- **STRATFI/TACFI and any matching arrangement are gated** on R8 and on a prime/program sponsor; no matching commitment is solicited or accepted by this document.
- The raise is **dilutive** and is the founder's decision; this document and the companion outline are **materials only** — no term sheet, no transaction, no capital movement is executed here.
- Valuation is **framed with ranges + comparables, never a fixed number** (see the outline).

### 3. Non-dilutive stacking

The investor narrative leads with the **non-dilutive stack already in motion** (NLnet + SBIR/CSO pipeline + audit threads) as proof the company extends runway and builds credibility *before* taking dilution — making any eventual round cheaper and better-positioned.

---

## Blended 24-Month Roadmap

> Quarters × streams × milestones. The TOTAL revenue **ESTIMATE band** below is **labeled assumptions, NOT guarantees** — read the per-stream gating before relying on any cell.

| Quarter | R1 Open-Core | R2 Federal/SBIR | R3 Grants | R4/R5/R6 Services & SaaS | R8 Investor (prepare-only) |
|---|---|---|---|---|---|
| **Q1 (mo 0-3)** | Publish + grow OSS funnel; line up 1-2 design partners | Apply: AFWERX Open Topic + DIU CSO; resolve >51% ownership w/ counsel | Track NLnet Restack (opens ~Sept); progress OSTIF/OTF audit threads | First R5 design-partner pilot ($0-25k) scoped | Draft dossier; map target investors |
| **Q2 (mo 3-6)** | Pilot delivery; case-study capture | Apply: 1-2 component topics + 1 civilian | Submit grant(s) as windows open | Pilot → custody-on-silicon proof (design-partner HW) | Refine valuation framing + comparables |
| **Q3 (mo 6-9)** | Team-tier pilots; pre-audit only | Phase I selection decisions begin (0-2); cash may lag to mo 9-15 | NLnet decision window | R6 training/cert offered (adoption-monetizing) | Non-dilutive stack as investor proof |
| **Q4 (mo 9-12)** | Audit in progress; harden binaries | First Phase I obligation/disbursement (lagged) | Grant cash (if awarded) | R5 standalone integration engagements | Optional first conversations (Brandon-run) |
| **Q5 (mo 12-15)** | Audit nearing complete; FTO engaged | Deliver Phase I cleanly → past performance | Stack next grant cycle | R4 managed-log SaaS early adopters | Decision: whether/when to raise |
| **Q6 (mo 15-18)** | ≥1 HSM custody path live; Team/Business sellable | Phase I→II proposal prep (~$750k-$1.2M modal) | — | R5/R6 attach to first paid subs | Prepare round materials (if go) |
| **Q7 (mo 18-21)** | First paying orgs (1-3, audit-gated) | Phase II selection (12-30mo event) | — | R4 control plane to early Business tier | STRATFI/TACFI matching prep (gated, w/ sponsor) |
| **Q8 (mo 21-24)** | $0-$200k ARR (estimate; upside 3-8 orgs if all gates landed early) | Phase II execution begins (if won); CMVP initiated | — | Services + support book growing | Raise (if pursued) — Brandon executes |

### Total revenue ESTIMATE band (labeled assumptions, NOT guarantees)

| Window | LOW | BASE | HIGH | Dominant source |
|---|---|---|---|---|
| **0-12 mo** | ~$0 (grant timing slips; 0 Phase I; pilots stall) | ~$50k-$150k (1 Phase I obligated + 1-2 pilots/services) | ~$300k-$450k (2 Phase I + NLnet + multiple pilots) | **Non-dilutive (R2+R3) + R5 pilots** |
| **12-24 mo** | ~$50k-$150k (audit slips; ARR ~$0; some services) | ~$200k-$500k (audit lands late-window; 1-3 paying orgs + services + a grant cycle) | ~$1.0M-$1.5M (Phase II won + audit early + 3-8 orgs converting) | **R2 Phase II + early R1/R4/R5 ARR** |
| **Cumulative 0-24 mo** | **~$50k-$300k** | **~$300k-$800k** | **~$1.5M-$2.5M** | Mix; non-dilutive-led early, recurring-led late |

**Assumptions behind the band (every one a stated assumption, not a fact):**

1. Per-shot SBIR/CSO win probability **10-15%**; 0-2 Phase I in year 1 (modal 1); award cash lags selection by 1-3+ months (0-15mo window).
2. Audit completes **somewhere in the 12-24mo window**; if it slips, ARR slips with it (LOW column).
3. First SaaS/Enterprise ARR is realistically **~$0 until mo 24-30**; the 12-24mo ARR cells are services/pilots-heavy in BASE, ARR-heavy only in HIGH.
4. Phase II ($750k-$1.2M modal, first-timer) only appears in **12-24mo HIGH** and only if a Phase I both lands and converts.
5. Grant (NLnet ~€45k) timing is **out of our control** (~Sept 2026 call); it sits in BASE/HIGH, not LOW.
6. **No number here is a booking, forecast, or guarantee.** The HIGH column requires multiple independent, currently-unsatisfied events to all land early; it is a ceiling, not a plan.

---

## Honest Status & Guardrails (closing)

This document is **strategy and materials only.** Before anyone acts on a single number in it:

- **UNAUDITED.** No independent security audit is complete. OSTIF + OTF Security Lab inquiries are *submitted*, not finished. Business/Enterprise tiers are not credibly sellable to regulated buyers until an audit lands.
- **Pre-product.** Nerion is in a Local/Private development posture. There is a reference implementation and a passing conformance suite — there is **no shipped commercial product**, no GA, no SLA in force.
- **CNSA-2.0-aligned, NOT validated.** Nerion is *aligned* with CNSA-2.0 / PQC guidance. It is **not** FIPS-140-3 validated and is **not** NSA-approved. Any FIPS value is the **HSM's** certificate, never Nerion's. Copy must always say "aligned," never "certified/validated."
- **Pre-FTO.** No freedom-to-operate opinion is on file. **No non-infringement claim**, and no "vs. the patented Commit-Point Gate" positioning, until counsel FTO is in hand. Sales/marketing stays on capability ("govern the verb"), not legal claims.
- **No current customers.** Zero paying customers today. Every pilot/ARR figure is a *future estimate*.
- **All numbers are estimates.** Every dollar figure is a **labeled estimate with stated assumptions**, grounded where possible in published program parameters and open-core comparables — **not** a booking, forecast, or guarantee. Bands (LOW/BASE/HIGH) are explicitly modeled scenarios, and the HIGH column requires multiple currently-unsatisfied events to all land.
- **Eligibility open items.** The SBIR >51%-US-ownership test (founder residency) and NLnet EU-substance are **live, unresolved** questions to settle with counsel — not assumed resolved.
- **Financial actions are the founder's, never automated.** No money is moved, no contract is signed, no raise is executed, and no matching arrangement is committed by this document or by any automated process. **Brandon (founder) runs any actual pricing, contracting, fundraising, custody deployment, or financial action.** STRATFI/TACFI and any private-capital matching are **prepare-only and gated** on the investor track + a program/prime sponsor.

*Prepared 2026-06-26. DRAFT. Strategy & materials only; no financial action is executed by this document.*
