# TRELYAN — Federal Capability Statement

**Company:** TRELYAN Inc. — US corporation, **100% owned by founder Brandon Sellam** (full US resident, New York)  
**Product:** Nerion — Post-Quantum Execution Governance Protocol for Autonomous AI Systems (one of TRELYAN's products)  
**Founded:** 2026 · **Location:** New York, NY (US) · **Business banking:** Mercury (US)  
**Website:** github.com/brandonjsellam-Releone/NERION  
**Point of Contact:** Brandon Sellam, Founder · brandon.sellam@gmail.com  
**License:** Apache-2.0 (open source)  
**NAICS:** 541519 (Other Computer Related Services) · 541715 (R&D in Engineering Sciences)

---

## Core Competency

Nerion is the first open-source **post-quantum execution governance protocol** for autonomous AI agent systems. Unlike cryptographic libraries or key management products that secure data at rest or in transit, Nerion secures **agent decisions at the point of execution** — applying post-quantum cryptographic authorization to every action an AI system proposes to take, before that action executes.

**The problem Nerion solves:** As federal agencies deploy AI-enabled systems for logistics, infrastructure management, and mission-critical operations, they face a dual vulnerability: (1) classical cryptographic controls protecting those systems are breakable by future quantum computers ("harvest now, decrypt later" attacks are already occurring), and (2) current AI governance frameworks rely on logging and monitoring rather than cryptographic enforcement. An adversary who harvests today's AI agent authorization tokens can forge commands years from now when quantum computers mature. Nerion eliminates both vulnerabilities simultaneously.

---

## Core Capabilities

| Capability | Technical Implementation | Evidence |
|---|---|---|
| **Post-quantum key encapsulation** | ML-KEM-1024 (NIST FIPS 203) | 23/23 conformance checks; KAT byte-exact |
| **Post-quantum digital signatures** | ML-DSA-87 (NIST FIPS 204) | CNSA 2.0 Category 5 aligned |
| **Hash-based signature backup** | SLH-DSA (NIST FIPS 205) | Conservative long-term root signing |
| **Symmetric channel security** | HMAC-SHA-384 + AES-256-GCM | CNSA 2.0 aligned |
| **AI agent policy enforcement** | Stateless deterministic `decide()` — default-deny, fail-closed | 469 automated tests |
| **Cryptographic action audit trail** | RFC 6962 Merkle log; tamper-evident, append-only | Inclusion + consistency proofs |
| **k-of-n quorum governance** | Threshold ML-DSA-87 over validator sets | ADR-0005; property-tested |
| **Negative oracle (govern-the-verb)** | Decision invariant to perception-shaped side data | Conformance check C14 |
| **Selective disclosure (ZK range proof)** | Bespoke Bulletproof-style over Pedersen commitments | Unaudited; CLASSICAL soundness |

---

## Differentiators

**1. Execution governance, not key management.** Nerion governs *decisions*, not storage. Every AI agent action — execute, authorize, delegate — is bound to a verifiable PQC signature before it happens. This is categorically different from an HSM or PKI system.

**2. "Govern the verb, never the eye."** Nerion's design-around principle: the admission decision is byte-identical regardless of what the AI system observed (perception data). This prevents adversaries from manipulating AI behavior by injecting false environmental data.

**3. Open source = auditable supply chain.** Apache-2.0 licensing means full transparency, no vendor lock-in, and zero supply-chain opacity. Federal evaluators can read, audit, and modify every line.

**4. Crypto-agile by design.** Algorithm identifiers are embedded in governance policies, not hardcoded. Algorithm rotation (e.g., when NIST finalizes additional standards) requires a policy update, not an architectural overhaul.

**5. Transatlantic alignment.** Nerion's design aligns with both NIST FIPS 203/204/205 and EU AI Act requirements for high-risk AI systems. Supports US-EU TTC interoperability goals.

---

## Current Status (Honest Assessment)

| Status Item | Current State |
|---|---|
| FIPS 140-3 CMVP validation | **Not initiated.** Algorithm selection is CNSA 2.0 aligned; module boundary not yet defined. |
| External security audit | **Submitted** audit inquiries to OSTIF and OTF Security Lab. Audit not yet contracted. |
| Patent clearance (FTO) | **Pre-FTO.** Legal review not yet completed. |
| Federal past performance | **None.** First government engagement expected via NIST NCCoE consortium. |
| NLnet grant funding | **Applying** to NLnet NGI Restack (call opens ~September 2026). Not yet funded. |
| Entity / SAM.gov registration | **Pending** (entity registration submitted; UEI forthcoming). US corporation; US business banking (Mercury) established 2026. |
| Test coverage | **469 tests** (72 test files) + **23/23 conformance checks** on published specification. |

---

## Alignment to June 2026 Executive Orders

| EO Requirement | How Nerion Addresses It |
|---|---|
| PQC algorithm adoption (FIPS 203/204/205) | All three NIST PQC standards implemented and conformance-tested |
| AI systems governance | Cryptographic policy enforcement on every AI agent action |
| Auditability and accountability | Merkle log with tamper-evident inclusion proofs on every decision |
| Quantum-resistant supply chain | Apache-2.0 open source; SBOM planned; SLSA provenance on roadmap |
| Contractor PQC standards (2030) | Architecture designed for contractor-side deployment |

---

## Past Performance / Comparable Experience

No formal federal past performance. Comparable technical work:

- Public protocol specification (github.com/brandonjsellam-Releone/NERION)
- 469-test suite with 23/23 conformance against published specification
- Rust hot-path implementation: 13 tests (9 unit + 4 KAT byte-exact against NIST vectors)
- Independent audit inquiries submitted June 2026

---

## Contact

**Brandon Sellam** — Founder, TRELYAN  
brandon.sellam@gmail.com  
New York, NY

*TRELYAN Inc. is a US corporation, **100% owned by Brandon Sellam, a full US resident in New York**. No foreign government has ownership, control, or influence over TRELYAN or Nerion (FOCI). US business banking: Mercury. All code is Apache-2.0 open source with no foreign-government control. The pending NLnet grant application is for independent European research funding; NLnet does not direct product or security decisions.*
