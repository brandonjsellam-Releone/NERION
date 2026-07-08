# NIST NCCoE PQC Migration Consortium — Inquiry Draft

> **Send to:** applied-crypto-pqc@nist.gov  
> **From:** Brandon Sellam, Founder, TRELYAN  
> **Subject:** Industry Partner Inquiry — Nerion PQ Execution Governance Protocol  
> **Timing:** Send within 72 hours of SAM.gov registration confirmation.

---

## Email Draft

**Subject:** Industry Partner Inquiry — Nerion PQ Execution Governance Protocol for AI Agent Systems

Dear NCCoE PQC Migration Consortium Team,

My name is Brandon Sellam. I am the founder of TRELYAN and the author of **Nerion**, an open-source post-quantum execution governance protocol for autonomous AI agent systems, published at github.com/brandonjsellam-Releone/NERION under the Apache-2.0 license.

I am writing to inquire about industry partnership with the NCCoE PQC Migration Consortium following President Trump's quantum executive orders of June 22, 2026.

**What Nerion is:**

Nerion is a protocol — not a cryptographic library — that governs _how_ autonomous AI agents exercise their authority. It applies ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204), and SLH-DSA (FIPS 205) to the _execution governance_ layer: every AI agent action is bound to a verifiable post-quantum signature before execution, creating a cryptographic chain of custody from policy issuance to execution. Symmetric operations use HMAC-SHA-384 and AES-256-GCM per the CNSA 2.0 suite.

The project currently passes **756 automated tests** across 102 test files, with **23/23 conformance checks** against the published specification. A Rust hot-path implementation passes 13 tests including byte-exact KAT comparisons against NIST vectors.

**Why we believe this is relevant to the Consortium:**

The June 2026 executive orders create a mandate not just for migrating cryptographic primitives but for securing the AI systems that increasingly operate on cryptographic authority. Nerion sits at the intersection of PQC migration and AI governance — both active federal mandates — and we believe it could serve as a useful reference implementation or test case for the Consortium's AI system migration guidance.

**Current status (full disclosure):**

- CNSA 2.0 algorithm alignment: ✓ (FIPS 203/204/205, HMAC-SHA-384, AES-256-GCM)
- FIPS 140-3 CMVP validation: not yet initiated
- Independent external audit: submitted inquiries to OSTIF and OTF Security Lab; not yet contracted
- Patent clearance: not yet obtained
- Apache-2.0 open source; no foreign-government funding or control

**What we are seeking:**

We are interested in learning more about the Consortium's current focus areas, whether Nerion's AI governance angle would be in scope for industry partnership or technical collaboration, and what the process would be for joining as an industry partner.

We are a small team and would be a research and technical contributor, not a commercial vendor seeking a procurement relationship. We understand the Consortium includes 50+ industry partners and that open-source projects are welcome.

I would welcome a brief call or email introduction to the appropriate team member.

Thank you for your consideration.

**Brandon Sellam**  
Founder, TRELYAN  
brandon.sellam@gmail.com  
New York, NY  
github.com/brandonjsellam-Releone/NERION

---

## Follow-up Strategy

**If no response in 2 weeks:** Follow up once, briefly. Reference the EO timing and mention that you have joined (or are joining) QED-C.

**If accepted:** Request to attend the next Consortium meeting or working group call. Ask about the Consortium's current focus areas and where AI governance + PQC intersects. Listen before pitching.

**If declined or out of scope:** Ask if there is another NCCoE team or project where AI governance + PQC would be more relevant. NIST's AI Risk Management Framework (AI RMF) team may be a better fit for the governance angle.
