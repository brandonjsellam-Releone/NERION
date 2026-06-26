# SAM.gov Registration & Federal Entry Checklist — TRELYAN

> **Entity:** TRELYAN · **Founder:** Brandon Sellam, US resident (New York, NY)  
> SAM.gov registration is mandatory for all US government contracting and consortium participation.

---

## Phase 0: Pre-Registration (Days 1–3)

### Step 0.1 — Confirm Entity Structure
- [ ] Confirm TRELYAN is registered as a US legal entity (LLC or C-Corp) in the state of New York
- [ ] Confirm Brandon Sellam is the registered agent or managing member
- [ ] Ensure the registered address is a physical, non-PO-Box US address (NYC address qualifies)
- [ ] Prepare DUNS/legal entity documentation for SAM.gov submission

**FOCI Note:** French-national founder + full US resident, 100% owner = straightforward disclosure. FOCI statement: "TRELYAN Inc. is a US corporation, **100% owned and controlled by Brandon Sellam, a French national who is a full US resident in New York, NY**. No foreign government has ownership, control, or influence over TRELYAN or its technology. US business banking is with Mercury. All Nerion code is Apache-2.0 open-source with no foreign-government licensing restrictions." *(Note: this FOCI statement is accurate on full residency; it deliberately does NOT assert "permanent resident alien / green card" — that specific immigration status is only needed for the SBIR ownership self-cert, see Step 3.1, and must be confirmed before use there.)*

### Step 0.2 — Determine if NCAGE Code is Needed
Brandon is a US resident with a US physical address. NCAGE codes are required for *foreign* companies without a US physical address. Since TRELYAN has a US address:
- [ ] **Skip NCAGE if TRELYAN is a US-registered LLC/Corp with a US address** — proceed directly to SAM.gov with the US EIN
- [ ] If TRELYAN is only registered outside the US: obtain NCAGE code first (10 business days) via NATO Support & Procurement Agency (nspa.nato.int)

### Step 0.3 — Prepare NAICS Codes
Primary NAICS codes for Nerion:
- **541519** — Other Computer Related Services (primary)
- **541715** — Research and Development in the Physical, Engineering, and Life Sciences
- **541512** — Computer Systems Design Services

---

## Phase 1: SAM.gov Registration (Days 3–7)

### Step 1.1 — Create Account
- [ ] Go to sam.gov → Create Account → choose "Entity Registration"
- [ ] Use your personal email address (brandon.sellam@gmail.com) initially, then add organizational email

### Step 1.2 — Core Data Section
- [ ] **Legal Business Name:** TRELYAN (exact legal name as registered)
- [ ] **Physical Address:** NYC address (must be non-PO Box)
- [ ] **EIN:** TRELYAN's federal tax ID number
- [ ] **Business Start Date:** TRELYAN formation date
- [ ] **Fiscal Year End:** Choose December 31

### Step 1.3 — Assertions Section
- [ ] **NAICS Codes:** 541519 (primary), 541715, 541512
- [ ] **Business Types:** Check all that apply: "US entity," "Small Business" (if <$15M revenue)
- [ ] **Disaster Relief Assistance:** Select No

### Step 1.4 — Representations & Certifications
- [ ] Read and certify the Federal Acquisition Regulation (FAR) clauses
- [ ] Pay attention to: FAR 52.209-5 (debarment/suspension certification), FAR 52.219-1 (small business program representations)
- [ ] **Foreign ownership disclosure:** If any section asks about foreign ownership, disclose Brandon's French nationality and US residency clearly and accurately

### Step 1.5 — Points of Contact
- [ ] **Government Business POC:** Brandon Sellam, brandon.sellam@gmail.com
- [ ] **Electronic Business POC:** Same
- [ ] **Past Performance POC:** Same (no past performance to report)

### Step 1.6 — Submit and Activate
- [ ] Submit registration → SAM.gov validates (typically 1–3 business days)
- [ ] Save the **Unique Entity ID (UEI)** — this is required for all subsequent federal interactions
- [ ] Annual renewal reminder: set calendar reminder for 11 months from registration date

---

## Phase 2: QED-C Membership (Week 2–3)

### Step 2.1 — Apply at quantumconsortium.org
- [ ] Go to quantumconsortium.org → Member Application
- [ ] QED-C is managed by SRI International, established by NIST
- [ ] Open to corporations internationally; US entity preferred but not required
- [ ] **Annual membership fee:** Typically $5,000–$15,000 for small companies (verify current rates)

### Step 2.2 — Membership Application Content
Include in your application:
- Company description: "TRELYAN is a US-based company developing Nerion, an open-source PQ execution governance protocol for autonomous AI agent systems, implementing NIST FIPS 203/204/205."
- Technical focus: "Post-quantum cryptographic governance of AI agent execution; CNSA 2.0 algorithm alignment; AI accountability and non-repudiation."
- Why QED-C: "Access to federal decision-makers shaping PQC procurement policy; alignment with NIST NCCoE PQC Migration Consortium."

### Step 2.3 — Follow-up
- [ ] After acceptance, identify the working groups most relevant: "PQC Implementation," "AI and Quantum," "Government Relations"
- [ ] Attend first available member meeting
- [ ] Connect with MITRE, Leidos, or Booz Allen Hamilton representatives at first meeting — these are your natural teaming partner targets

---

## Phase 3: AFWERX SBIR Preparation (Month 2–4)

### Step 3.1 — SBIR Eligibility Verification
- [x] **Ownership concentration: MET** — Brandon owns **100%** of TRELYAN Inc. (sole owner; no co-owner, no VC-ownership path, no control ambiguity).
- [ ] **Remaining SBIR ownership test = ONE fact:** SBIR/STTR requires >50% ownership by a US **citizen or permanent-resident alien (green-card holder)** (13 CFR 121.702). A "full US resident" is **not automatically** a "permanent resident alien" — green card or citizenship is the specific status. **Confirm Brandon's immigration classification with a GovCon attorney before signing the SBIR self-certification.** (The self-cert is a legal attestation; an inaccurate one carries False-Claims exposure.) This does NOT gate the non-SBIR track (NCCoE, QED-C, DIU, SAM).
- [ ] Confirm employee count <500 (required for Small Business designation)

### Step 3.2 — Monitor AFWERX Solicitations
- [ ] Bookmark afwerx.com/sbir-sttr
- [ ] Set up SAM.gov email alerts for NAICS codes 541519 and 541715
- [ ] Target solicitation topics: "Post-Quantum Cryptography," "Autonomous Systems Security," "AI Assurance," "Zero-Trust for AI"

### Step 3.3 — Draft SBIR Phase I Technical Volume
Key elements to include (based on Nemotron council analysis):

**Title:** "Post-Quantum Execution Governance for Autonomous AI Agent Systems"

**Phase I Objective:** Demonstrate sub-500μs P99 governance round-trip for a 10-agent autonomous system scenario using ML-DSA-87 (FIPS 204) policy authorization, with deterministic behavior under NIST KAT vectors.

**Technical Innovation:** Unlike existing PQC libraries or HSM solutions that secure keys or communications, Nerion governs *execution* — every AI agent action is bound to a verifiable PQC signature before execution, creating a cryptographic chain of custody from policy issuance through action completion.

**CNSA 2.0 Alignment:** ML-KEM-1024 (FIPS 203) for session establishment, ML-DSA-87 (FIPS 204) for action authorization signatures, SLH-DSA (FIPS 205) for root policy signing, AES-256-GCM + HMAC-SHA-384 for record protection.

**Phase I Deliverables:**
1. Performance benchmark suite: criterion.rs + perf, reproducible build
2. FIPS 140-3 module boundary design document
3. CNSA 2.0 compliance mapping (algorithm-by-algorithm)
4. Integration prototype with representative DoD AI agent scenario

**Dual-Use Applications:** Loyal wingman/CCA swarm governance; CDAO ADA zero-trust AI mesh; autonomous logistics; DARPA AIE verifiable agent chains.

---

## Phase 4: Prime Teaming (Month 6+)

### Best Prime Targets
| Prime | Why | How to Approach |
|---|---|---|
| **MITRE** | NCCoE work; open-source friendly; CISA relationship | Via NCCoE consortium introduction |
| **Booz Allen Hamilton** | Heavy QED-C participant; large PQC portfolio | Via QED-C member network |
| **Leidos** | Major DoD AI and cyber programs | Via QED-C or AFWERX connections |
| **IBM Federal** | Has PQC roadmap; AI governance practice | Direct outreach after NCCoE partnership |

### Teaming Agreement Essentials
- Nerion contributes: the protocol, PQC implementation, open-source stack, technical IP
- Prime contributes: past performance, procurement vehicle, cleared facility (if needed), business development
- Revenue split: typically 20–40% to sub for technology, 60–80% to prime for program management + BD
- IP: retain Nerion protocol IP; grant prime a license for the specific program

---

## Compliance Reminders

| Requirement | Status | Action |
|---|---|---|
| SAM.gov active registration | ⬜ **Pending** | Submitted; awaiting SAM validation (2026-06-26). Daily watcher auto-flags Active + UEI |
| UEI obtained | ⬜ Pending SAM | Auto-generated at registration |
| US business banking | ✅ Done | Mercury (TRELYAN Inc.), 2026 — provides the SAM financial/EFT details |
| Ownership | ✅ Confirmed | TRELYAN Inc. **100% owned** by Brandon Sellam (full US resident, NY) |
| Foreign nationality disclosed | ✅ Drafted | French national, full US resident; in all federal materials |
| FOCI mitigation documented | ✅ Drafted | 100%-owned US-corporation statement in all proposals |
| SBIR ownership eligibility | ⬜ Confirm | 100% owned; confirm Brandon is citizen / green-card holder before SBIR self-cert |
| NLnet grant disclosed | ⬜ Not yet needed | Include in any federal proposal mentioning funding |
| FIPS 140-3 CMVP status | ⬜ Not initiated | State accurately: "evaluation phase; CMVP initiation planned" |
| External audit status | ⬜ Inquiries submitted | State accurately: "audit inquiries submitted; contract not yet signed" |

---

*This checklist was developed with input from a 10-model council including federal procurement expertise (Grok, WatsonX, Perplexity), technical due diligence (DeepSeek, Nemotron), and EU-US regulatory analysis (Mistral). Always verify current SAM.gov requirements at sam.gov as procedures update regularly.*
