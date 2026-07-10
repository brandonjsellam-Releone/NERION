# Nerion / TRELYAN — US Government PQC Outreach Strategy

> **Status:** Strategic planning document. Internal use only.  
> **Context:** President Trump signed two landmark quantum executive orders on June 22, 2026 — two days ago — opening the most significant federal PQC procurement window in US history.  
> **Entity:** TRELYAN · Founder: Brandon Sellam, French national, US resident (NYC) · Product: Nerion, Apache-2.0.

---

## 1. The Strategic Moment

On June 22, 2026, the White House signed:

1. **"Ushering in the Next Frontier of Quantum Innovation"** — mandates all federal agencies adopt post-quantum cryptography by **2030–2031** (accelerated from the prior 2035 target), establishes a nationwide PQC Migration Pilot by December 31, 2027, directs the FAR Council to require covered contractors to meet PQC standards by end of 2030, and commits **$2 billion in grants** across nine quantum computing firms.

2. **"Securing the Nation Against Advanced Cryptographic Attacks"** — requires NSA, CISA, and OMB to coordinate PQC migration for national security systems; directs federal departments to assist allied governments and industry in PQC transition; explicitly names NASA and GSA for PQC cost-saving coordination.

Additionally, CISA issued mandatory procurement guidance in January 2026 directing federal agencies to **buy only PQC-capable products** in categories where they are widely available — cloud, web, endpoint security, and more.

The window is open **right now**. Agencies are required to begin transitioning immediately. The 2027 pilot program will generate significant procurement activity. This is the optimal moment for Nerion to establish federal relationships.

---

## 2. Nerion's Unique Positioning

### The Dual-Mandate Advantage

Most PQC vendors address only the first mandate: migrate cryptographic primitives to FIPS 203/204/205. Nerion addresses **two simultaneous federal mandates**:

| Federal Mandate                                 | What Most Vendors Deliver     | What Nerion Delivers                                           |
| ----------------------------------------------- | ----------------------------- | -------------------------------------------------------------- |
| PQC Cryptographic Migration (June 2026 EOs)     | PQC library / HSM integration | ML-KEM-1024 + ML-DSA-87 + SLH-DSA governing AI agent execution |
| AI Governance / Oversight (E.O. 14110 + AI RMF) | Access control logs           | Cryptographic chain-of-custody for every AI agent decision     |

No commercial vendor currently occupies this intersection. Entrust, Thales, and IBM secure **keys**. Nerion secures **agent decisions** — with PQC, with auditable policy, at execution time.

### The Core Differentiator

> _"Nerion enforces post-quantum cryptographic authorization on every AI agent action, binding execution to policy via NIST-aligned lattice and hash-based signatures that remain unforgeable even under harvest-now-decrypt-later attacks."_

This is **not** a PQC library. It is a **governance protocol** — the policy _is_ the protocol. Think of it as cryptographically-signed Rules of Engagement for AI agents: they travel with the agent, are checked at every action boundary, and cannot be forged even by a quantum adversary.

### Technical Positioning (Honest)

| Claim                                | Evidence                                                         | Caveat                                                                                             |
| ------------------------------------ | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| FIPS 203/204/205 algorithm alignment | ML-KEM-1024, ML-DSA-87, SLH-DSA implemented + conformance-tested | **CNSA 2.0 aligned — not FIPS 140-3 certified.** CMVP validation not yet started.                  |
| 756 tests, 24/24 conformance checks  | `npm run gate` + `npm run conformance`                           | Demonstrates implementation consistency with Nerion's own spec — not external security validation. |
| Open-source, auditable supply chain  | Apache-2.0, GitHub public                                        | **Externally UNAUDITED.** Audit inquiries submitted to OSTIF and OTF Security Lab.                 |
| Rust hot-path, TypeScript core       | 13 Rust tests (9 unit + 4 KAT)                                   | Production deployment requires FIPS 140-3 validated crypto boundary.                               |

**What to say:** "Nerion's algorithm selection matches the CNSA 2.0 suite — ML-KEM-1024, ML-DSA-87, SLH-DSA, HMAC-SHA-384, AES-256-GCM. We have not yet completed FIPS 140-3 CMVP validation; we are in the research and consortium-engagement phase and will pursue validation as federal engagement deepens."

---

## 3. Entry Channel Strategy

### Recommended Pursuit Order

**Phase 0 — Immediate (Week 1–2):**

1. **SAM.gov registration** — mandatory foundation for every subsequent step. As a US-resident founder with a physical NYC address, this is straightforward. No US bank account required for initial registration.
2. **QED-C membership** — lowest-friction entry point for visibility with NIST, CISA, and industry primes. Open to international companies. Apply at quantumconsortium.org.

**Phase 1 — Near-term (Month 1–3):** 3. **NIST NCCoE PQC Migration Consortium** — contact applied-crypto-pqc@nist.gov. 50+ industry collaborators (AWS, Cisco, Google, IBM, Microsoft). Accepts open-source projects as industry partners. This is the single highest-credibility federal engagement vehicle for a new entrant without past performance. 4. **CISA engagement** — present Nerion as a reference implementation for CISA's PQC Migration Playbook. Contact CISA's cybersecurity division directly after NCCoE contact.

**Phase 2 — Growth (Month 3–6):** 5. **AFWERX SBIR Phase I** — submit a topic on "PQC governance of autonomous AI agents." AFWERX is tolerant of open-source and small teams. Creates the first federal past performance reference. Target: AFWERX SBIR solicitation, Q3–Q4 2026. 6. **DIU Commercial Solutions Opening (CSO)** — Defense Innovation Unit accepts technology proposals from non-traditional vendors. The "PQC AI governance" angle fits DIU's dual-use technology mandate.

**Phase 3 — Scale (Month 6–18):** 7. **Subcontracting to a US prime** — use SBIR/NCCoE reference as credentialing. Target primes: Booz Allen Hamilton, Leidos (heavy QED-C/NIST presence), MITRE (NCCoE and CISA work, open-source friendly), IBM Federal. 8. **GSA Schedule** — pursue only after at least one federal delivery order or SBIR success.

**What NOT to do:**

- Do not blast unsolicited capability statements to agency program managers the week after the EO — every vendor is doing this. Stand out by being specific and technically credible.
- Do not pursue GSA Schedule or a prime contract as the first action.
- Do not claim "government-ready," "FIPS-certified," or "production-ready" without audit and certification. Credibility is everything in federal procurement.

---

## 4. Key Risks and Mitigations

### Risk 1: Foreign Ownership, Control, or Influence (FOCI)

**The issue:** Brandon Sellam is a French national (US resident, NYC). PQC is dual-use technology. DoD environments may trigger FOCI review, which can delay or block engagement.

**Mitigation:**

- Establish a clean US C-Corp (TRELYAN LLC / Inc.) with Brandon as sole member/director; document clearly that all IP is US-domiciled and Apache-2.0 open-source.
- State proactively in all federal materials: "TRELYAN is a US-based company. The founder is a US resident. All code is Apache-2.0 open-source with no foreign-government funding or control. Pending EU NLnet grant application is for independent research; NLnet does not direct development priorities."
- France is a NATO ally and not a "country of concern" under CFIUS. Proactive disclosure eliminates uncertainty.

### Risk 2: No FIPS 140-3 Validation

**The issue:** Federal agencies protecting SBU/CUI/PII cannot deploy unvalidated crypto in production.

**Mitigation:**

- Engage as a research/consortium partner (NCCoE, QED-C) rather than a production vendor in the first 12 months.
- Commit to initiating FIPS 140-3 CMVP validation process as part of Phase 2 engagement (define module boundary, engage an accredited CST lab).
- Frame current status as: "evaluation-and-development-phase deployment, with CMVP process to follow federal engagement."
- Path: wrap or integrate with `aws-lc-rs` (FIPS 140-3 cert #4764) rather than a full self-certification for faster federal adoption.

### Risk 3: No External Security Audit

**The issue:** "UNAUDITED" status raises credibility flags with federal evaluators.

**Mitigation:**

- Lead with audit submission: "We have submitted independent audit inquiries to OSTIF and OTF Security Lab and are actively seeking a qualified cryptographic auditor."
- 756 tests + 24/24 conformance provide deterministic behavior evidence. Frame as: "Reproducible coverage metrics and deterministic behavior under test vectors suitable for government evaluation environments."
- The NCCoE consortium engagement itself creates peer review from federal-grade evaluators.

### Risk 4: No Prior Government Performance

**The issue:** Past performance is heavily weighted in federal procurement.

**Mitigation:**

- NCCoE industry partnership creates a government-trackable engagement even without a contract.
- QED-C membership creates peer references from companies with extensive past performance.
- SBIR Phase I ($50–150K) creates the first official federal past performance record.

---

## 5. The EU-US Bridge Narrative

Brandon Sellam's French-American profile and the pending NLnet NGI Restack grant application (call opens ~September 2026) are **assets**, not liabilities, when framed correctly.

**For CISA/NIST:** "NLnet's support lets us build Nerion's PQC governance stack faster, so US agencies can adopt it sooner. We are seeking US government co-evaluation to ensure alignment with NIST standards."

**For DoD/NSA:** "Nerion is the first open-source PQC governance protocol designed to bridge the EU AI Act's high-risk PQC requirements and NIST's FIPS 203/204 standards. Open-source and Apache-2.0 means no foreign licensing restrictions and full supply-chain transparency — a democratic-aligned alternative to state-backed Chinese PQC standards (SM2/3)."

**For State Department:** "Nerion positions as an EU-US technology bridge: a transatlantic public good that reduces fragmentation between allied-nation PQC governance approaches."

**Bilateral programs to target alongside SAM.gov:**

- **US-EU Trade and Technology Council (TTC)** — "Trusted AI" and "Secure Supply Chains" workstreams
- **NATO DIANA** — "Quantum-Safe Communications" challenge (dual-use tech accelerator for allied nations)
- **CISA PQC Migration Working Group** — request to present at quarterly PQC syncs

**NLnet disclosure:** Proactively disclose the pending NLnet application in all federal materials. Frame it as a European research-phase grant; emphasize Apache-2.0 licensing means no EU-specific restrictions. The USG sees "transatlantic cost-sharing" as a positive.

---

## 6. Agency Priority Matrix

| Agency           | Why Now                                                                             | Best Entry                                 | Fit Score |
| ---------------- | ----------------------------------------------------------------------------------- | ------------------------------------------ | --------- |
| **NIST / NCCoE** | Running PQC Migration Consortium; actively recruits open-source projects            | applied-crypto-pqc@nist.gov                | ★★★★★     |
| **CISA / DHS**   | Issued Jan 2026 procurement mandate; needs reference implementations for AI systems | CISA cybersecurity liaison; NCCoE referral | ★★★★☆     |
| **AFWERX / DoD** | Active SBIR; dual-use autonomous AI + PQC is a perfect topic                        | AFWERX SBIR solicitation portal            | ★★★★☆     |
| **DIU**          | CSO process for non-traditional vendors; AI governance mandate                      | DIU.mil CSO submission                     | ★★★☆☆     |
| **NSA**          | CNSA 2.0 requirements; highest-value but lowest accessibility for new entrants      | Via QED-C / prime teaming                  | ★★★☆☆     |
| **NASA / GSA**   | Named in June 2026 EO; procurement vehicles available post-SAM                      | SAM.gov → GSA Schedule (Year 2)            | ★★☆☆☆     |

---

## 7. 90-Day Action Plan

| Week | Action                                                                         | Owner   | Output                             |
| ---- | ------------------------------------------------------------------------------ | ------- | ---------------------------------- |
| 1    | Complete SAM.gov registration (UEI + CAGE/NCAGE)                               | Brandon | Active SAM registration            |
| 1    | Draft and send NIST NCCoE inquiry email                                        | Brandon | Introduction established           |
| 2    | Apply for QED-C membership                                                     | Brandon | Membership application submitted   |
| 2    | Contact CISA cybersecurity division re: PQC Migration Playbook                 | Brandon | Meeting or follow-up scheduled     |
| 3–4  | Commission independent security audit (OSTIF / OTF or third auditor)           | TRELYAN | Audit contract signed              |
| 4–6  | Identify and approach US prime teaming partner (Leidos, BAH, MITRE)            | Brandon | LOI or teaming agreement initiated |
| 6–8  | Monitor AFWERX SBIR solicitations; draft Phase I proposal on PQC AI governance | TRELYAN | SBIR draft ready                   |
| 8–12 | Submit AFWERX SBIR Phase I                                                     | TRELYAN | Proposal submitted                 |
| 12   | Apply to NATO DIANA quantum-safe communications cohort                         | Brandon | Application submitted              |

---

## 8. Messaging Guardrails

**Always say:**

- "CNSA 2.0 aligned — not FIPS 140-3 certified"
- "Externally unaudited; audit in process"
- "Pre-FTO; patent clearance not yet obtained"
- "Applying to NLnet; not yet funded"
- "756 tests and 24/24 conformance checks — implementation consistency, not external validation"

**Never say:**

- "FIPS-certified," "FIPS-validated," "NSA-approved," "CISA-approved"
- "Production-ready," "government-ready," "secure," "proven"
- "Audited," "certified," "cleared"
- "Revolutionary," "first-of-its-kind," "unbreakable," "100% secure"
- "Funded by NLnet" (we are _applying_, not funded)

---

_Document version: 2026-06-24 · 10-model council review: DeepSeek, Grok, OpenAI, Gemini, WatsonX, Mistral, Hermes, Nemotron (NVIDIA), Perplexity, Claude Opus 4.8_
