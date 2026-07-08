# Nerion — US Government Agency Opportunity Matrix

> Based on 10-model council analysis (DeepSeek, Grok, OpenAI, Gemini, WatsonX, Mistral, Hermes, Nemotron, Perplexity, Claude Opus 4.8)  
> Rating system: ★★★★★ = highest priority · ★☆☆☆☆ = lowest priority  
> Ratings: Urgency (time sensitivity of the open window) · Fit (how well Nerion matches the need) · Access (how reachable is this for a new entrant without past performance)

---

## 1. NIST / NCCoE — PQC Migration Consortium

| Dimension   | Detail           |
| ----------- | ---------------- |
| **Urgency** | ★★★★★            |
| **Fit**     | ★★★★★            |
| **Access**  | ★★★★☆            |
| **Overall** | **TOP PRIORITY** |

**Their specific PQC need:** The NCCoE is actively running a PQC Migration Consortium with 50+ industry collaborators to develop practical migration guidance. They need diverse technical inputs — especially for AI-related system categories (AI agent infrastructure is not yet well-represented). The June 2026 EOs give them mandate to accelerate.

**How Nerion fits:** Open-source, protocol-level PQC implementation that demonstrates FIPS 203/204/205 in an AI governance context. This is precisely the kind of reference implementation NCCoE seeks. Apache-2.0 means no IP entanglement.

**Best entry point:** Email applied-crypto-pqc@nist.gov. See `docs/gov/NIST-NCCO-INQUIRY.md` for the draft. NIST is uniquely accessible to open-source projects — they welcome contributors without past performance or commercial products.

**Key risk:** Nerion's "governance" angle may seem out of scope for a consortium focused on cryptographic migration. Frame the outreach specifically around the PQC algorithm implementation and conformance testing, with the governance layer as a value-add. Don't lead with "AI agent governance" — lead with "FIPS 203/204/205 implementation with conformance testing."

**Key action:** Send inquiry email within 72 hours of SAM.gov registration. Mention the June 2026 EOs explicitly — they have mandate pressure and are actively looking for contributors.

---

## 2. CISA / DHS — PQC Product Procurement Guidance

| Dimension   | Detail            |
| ----------- | ----------------- |
| **Urgency** | ★★★★★             |
| **Fit**     | ★★★★☆             |
| **Access**  | ★★★☆☆             |
| **Overall** | **HIGH PRIORITY** |

**Their specific PQC need:** CISA's January 2026 procurement guidance mandates that federal agencies buy only PQC-capable products. CISA is developing and maintaining the PQC Product List — a catalog of products that implement FIPS 203/204/205. They also need guidance for AI systems specifically, which current PQC product lists don't address well.

**How Nerion fits:** Nerion can serve as a reference implementation showing how AI agent systems can be made PQC-capable. The "govern the verb" design principle directly addresses CISA's concern about AI systems acting outside authorized boundaries. CISA's Binding Operational Directives (BODs) for Federal Civilian Executive Branch (FCEB) agencies create a procurement mandate that Nerion can address.

**Best entry point:**

1. Engage via the NCCoE pathway first (NIST/CISA have overlapping working groups)
2. Contact CISA's PQC Migration Working Group directly after NCCoE introduction
3. Review CISA's PQC Migration Playbook and submit Nerion as a potential reference implementation

**Key risk:** CISA focuses on production-ready, deployable products. Nerion's UNAUDITED status is a blocker for CISA's product list. Initial engagement should be framed as "reference implementation for the AI systems category" — a research/guidance contribution, not a procurement offer.

**Talking point:** "CISA's January 2026 guidance requires PQC for both core and secondary functions. Nerion demonstrates how to implement PQC at the execution governance layer — the action authorization path — not just the communication layer."

---

## 3. AFWERX / DoD — SBIR for Autonomous AI Systems

| Dimension   | Detail            |
| ----------- | ----------------- |
| **Urgency** | ★★★★☆             |
| **Fit**     | ★★★★★             |
| **Access**  | ★★★★☆             |
| **Overall** | **HIGH PRIORITY** |

**Their specific PQC need:** DoD AFWERX runs SBIR/STTR programs specifically for innovative dual-use technologies. The combination of autonomous AI agent governance + PQC is a near-perfect topic for AFWERX's "Quantum + Cyber" solicitations. AFWERX specifically values open-source, non-traditional vendors and small teams.

**How Nerion fits:** The NVIDIA Nemotron analysis identified the exact DoD programs:

- **CDAO ADA (Advancing Data & AI):** Needs "zero-trust AI agent mesh" — Nerion is the policy fabric
- **DARPA AIE / ANCE:** Autonomous agents requiring verifiable execution chains
- **AFRL Vanguard "Skyborg" / CCA (Collaborative Combat Aircraft):** Loyal wingman agents need PQC-signed Rules of Engagement compliance

**Best entry point:** AFWERX SBIR solicitation portal (afwerx.com). Target a Phase I proposal ($50–150K) on "PQC Governance of Autonomous AI Agents." See the SBIR pitch language in `docs/gov/SAM-REGISTRATION-CHECKLIST.md`.

**Key risk:** SBIR requires 51%+ US ownership. Brandon is a US resident but French national. Ensure the US C-Corp entity structure is clean and clearly documented. The entity must be majority-US-owned for SBIR eligibility.

**Key differentiator for DoD pitch:** "An adversary who captures today's AI agent authorization tokens can forge commands when quantum computers mature. Nerion eliminates this attack surface by binding every agent action to a PQC signature that even a quantum adversary cannot forge."

**Benchmark they'll want:** Sub-500μs P99 governance round-trip on commodity hardware for a 10-agent swarm scenario. Nerion must demonstrate this before a Phase II engagement.

---

## 4. DIU — Commercial Solutions Opening (CSO)

| Dimension   | Detail          |
| ----------- | --------------- |
| **Urgency** | ★★★☆☆           |
| **Fit**     | ★★★★☆           |
| **Access**  | ★★★★☆           |
| **Overall** | **MEDIUM-HIGH** |

**Their specific PQC need:** Defense Innovation Unit (DIU) accepts technology proposals via Commercial Solutions Opening (CSO) process — designed specifically for non-traditional vendors (including small companies and open-source projects) with technologies DoD can adapt for defense use. DIU's AI/ML portfolio includes autonomous systems governance.

**How Nerion fits:** DIU has funded AI governance and security tools in the past. The PQC + AI governance combination is a dual-use technology that fits DIU's mandate. DIU is explicitly designed to bridge commercial innovation and DoD needs, making it more accessible than traditional DoD procurement.

**Best entry point:** DIU.mil → Solutions → CSO process. Submit a two-page Technical Volume describing Nerion's capability. No SAM registration required for initial CSO submission (though required if selected).

**Key risk:** DIU typically wants technologies closer to production readiness than Nerion's current state. Frame as "evaluation and adaptation for defense AI platforms" rather than a production deployment offer.

---

## 5. NSA — National Security Systems PQC Migration

| Dimension   | Detail                    |
| ----------- | ------------------------- |
| **Urgency** | ★★★★★                     |
| **Fit**     | ★★★★☆                     |
| **Access**  | ★★☆☆☆                     |
| **Overall** | **STRATEGIC / LONG-TERM** |

**Their specific PQC need:** NSA's CNSA 2.0 suite mandates PQC for all national security systems by 2030. NSA also governs Commercial Solutions for Classified (CSfC) — a framework allowing commercial products to protect classified data when layered appropriately. AI governance at the PQC level is directly relevant.

**How Nerion fits:** Nerion's CNSA 2.0 alignment (ML-KEM-1024, ML-DSA-87, AES-256-GCM, HMAC-SHA-384) is a prerequisite. The governance layer maps to NSA's requirement for accountable AI systems on classified networks.

**Best entry point:** NSA is not directly accessible for new vendors without past performance or a prime contractor relationship. Path: (1) establish NCCoE partnership, (2) engage via a prime (Leidos, Booz Allen, MITRE), (3) approach NSA's Cybersecurity Collaboration Center once relationship established.

**Key risk:** NSA will require FIPS 140-3 validation, supply chain attestation, and cleared personnel for any meaningful engagement. This is a 2–3 year trajectory, not a 90-day action.

**Talking point for when the time comes:** "Nerion's CNSA 2.0 aligned implementation, combined with GPU TEE attestation (NVIDIA H100 CC mode), provides a layered PQC+hardware-attestation stack for autonomous AI systems operating in classified environments."

---

## 6. NASA / GSA — EO-Named Agencies

| Dimension   | Detail              |
| ----------- | ------------------- |
| **Urgency** | ★★★☆☆               |
| **Fit**     | ★★☆☆☆               |
| **Access**  | ★★★☆☆               |
| **Overall** | **MEDIUM / YEAR 2** |

**Their specific PQC need:** NASA and GSA were explicitly named in the June 2026 EO for PQC cost-saving coordination. NASA has autonomous systems (space robotics, mission control AI) that could benefit from Nerion's governance approach. GSA provides the procurement vehicles (GSA Schedules) that many agencies use.

**How Nerion fits:** NASA's autonomous mission systems and GSA's role as procurement clearinghouse make these agencies relevant for Year 2+ engagement once Nerion has NCCoE/AFWERX credentialing.

**Best entry point:** GSA Schedule (Year 2, after past performance established). For NASA: contact NASA's cybersecurity or AI governance team via QED-C network connections.

**Priority:** Lower than NIST/CISA/AFWERX. Pursue opportunistically via QED-C connections rather than direct outreach.

---

## Quick Reference Matrix

| Agency         | 30-Day Action      | Primary Contact             | Blocker                                |
| -------------- | ------------------ | --------------------------- | -------------------------------------- |
| **NIST NCCoE** | Send inquiry email | applied-crypto-pqc@nist.gov | None — very accessible                 |
| **CISA**       | Engage post-NCCoE  | Via NCCoE referral          | UNAUDITED status                       |
| **AFWERX/DoD** | Draft SBIR Phase I | afwerx.com SBIR portal      | US entity structure (SBIR eligibility) |
| **DIU**        | Submit CSO         | diu.mil                     | Production readiness                   |
| **NSA**        | Queue for Year 2   | Via prime teaming           | FIPS 140-3 + clearances                |
| **NASA/GSA**   | Queue for Year 2   | Via QED-C                   | Past performance                       |
