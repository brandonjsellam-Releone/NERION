# QED-C Membership Application — TRELYAN Supporting Materials

> **Target:** Quantum Economic Development Consortium (QED-C)  
> **URL:** quantumconsortium.org  
> **About:** Established by NIST, managed by SRI International. 250+ members. Open to international companies.  
> **Timing:** Apply within 2 weeks of SAM.gov registration.

---

## Company Profile (for application form)

**Legal Name:** TRELYAN Inc. (US corporation, **100% owned by founder Brandon Sellam, a US citizen**)  
**Location:** New York, NY, USA · **Business banking:** Mercury (US)  
**Website:** github.com/brandonjsellam-Releone/NERION  
**Primary Contact:** Brandon Sellam, Founder · brandon.sellam@gmail.com  
**Employee Count:** [Current headcount]  
**Annual Revenue:** [Current revenue — small business if <$15M]

---

## Technology Description (for application)

TRELYAN develops **Nerion**, an open-source post-quantum execution governance protocol for autonomous AI agent systems.

**What Nerion does:** Nerion cryptographically governs what autonomous AI agents are permitted to do, using NIST-finalized post-quantum standards (FIPS 203, 204, 205). Every AI agent action — authorize, execute, delegate — is bound to a verifiable post-quantum signature before execution. Nerion creates a cryptographic chain of custody for AI decisions that remains unforgeable even under quantum adversaries.

**Why this matters for quantum:** AI systems operating today are making decisions authorized by classical cryptographic credentials. A "harvest now, decrypt later" adversary capturing those credentials today can forge AI agent authorizations when quantum computers mature. Nerion eliminates this vulnerability by applying ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204), and SLH-DSA (FIPS 205) to the execution governance layer — not just communications.

**Technical status:** 469 automated tests + 23/23 conformance checks against the published specification. Rust hot-path with 13 tests including byte-exact KAT comparisons against NIST vectors. Apache-2.0 open-source. CNSA 2.0 algorithm aligned (not FIPS 140-3 certified — CMVP process not yet initiated). External audit inquiries submitted to OSTIF and OTF Security Lab.

**Federal alignment:** Aligned to June 2026 quantum executive orders (PQC migration by 2030–2031). Addresses both the PQC cryptographic migration mandate and the parallel AI governance mandate simultaneously.

---

## Membership Objectives (why we're joining QED-C)

1. **Technical collaboration** with the federal quantum community on PQC implementation standards for AI systems
2. **Policy input** on PQC migration guidance for AI agent architectures (currently underrepresented in existing guidance)
3. **Networking** with prime contractors and agencies to identify federal engagement pathways
4. **Standards alignment** — ensure Nerion's approach aligns with evolving NIST, CISA, and NSA guidance

---

## Relevant Working Group Interests

| Working Group | Relevance to Nerion |
|---|---|
| PQC Implementation | Core: FIPS 203/204/205 implementation and conformance |
| AI and Quantum | Dual mandate: PQC + AI governance intersection |
| Government Relations | Federal procurement and consortium engagement |
| Cybersecurity | CNSA 2.0 alignment; supply chain security (Apache-2.0) |

---

## Positioning Within QED-C

Nerion occupies a unique position in the quantum ecosystem that complements rather than competes with most QED-C members:

- **Not a hardware company** (no QPU, no ion trap, no photonics)
- **Not a generic PQC library** (Entrust, Thales, IBM handle key management)
- **Fills a gap:** post-quantum governance of the AI execution layer — the action authorization path that existing PQC vendors don't address

The framing within QED-C:
> "Nerion is the policy enforcement layer that makes AI-driven federal systems quantum-resistant — not at the communication layer, but at the decision layer."

---

## Conversation Starters for First QED-C Meeting

When meeting other QED-C members for the first time:

**For NIST staff:** "We've submitted an industry partner inquiry to the NCCoE PQC Migration Consortium. We'd welcome guidance on how AI agent governance fits within the consortium's scope."

**For prime contractors (Leidos, BAH, MITRE):** "We're exploring teaming opportunities for SBIR or OTA proposals on PQC governance of autonomous systems. Nerion is Apache-2.0 — we can integrate with your existing PQC stack."

**For agency program managers:** "Which parts of your AI systems roadmap are most affected by the June 2026 PQC executive orders? We're specifically interested in the agent authorization and execution path."

**For crypto vendors (Entrust, Thales, IBM):** "We're not a competing key management product — we're the governance layer above the HSM. We've designed Nerion to integrate with PKCS#11 interfaces so it can use your HSM for root key material while handling agent policy enforcement above the HSM layer."

---

## NLnet Grant Disclosure

*Include this proactively if asked about funding or international affiliations:*

"TRELYAN is applying to the NLnet NGI Restack research grant program (European, call opens approximately September 2026). We are not yet funded — the application is pending. NLnet is an independent Dutch foundation that funds open-source research; it does not direct product development or security decisions. All Nerion code is Apache-2.0 with no EU-specific licensing restrictions. We view the potential NLnet grant as a transatlantic force multiplier for USG priorities — European research funding accelerating US-standard PQC implementation that federal agencies can then evaluate and adopt."

---

## Follow-up Plan Post-Membership

| Month | Action |
|---|---|
| 1 | Attend first available member meeting or working group call |
| 1 | Connect with MITRE, Leidos, or Booz Allen Hamilton representatives |
| 2 | Request to present Nerion at a working group technical session |
| 3 | Identify specific SBIR or OTA topics to co-develop with a prime |
| 6 | Leverage QED-C membership as reference in AFWERX SBIR proposal |

---

*QED-C membership gives TRELYAN direct visibility with government decision-makers shaping quantum policy and procurement. The 250+ member network is the fastest path to building the federal relationships needed for SBIR and prime teaming, without requiring past performance.*
