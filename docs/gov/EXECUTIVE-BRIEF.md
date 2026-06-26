# Nerion — Executive Brief for Federal Meetings

> **One-page briefing** for agency meetings, program manager introductions, and investor/partner conversations.  
> **Audience:** CISA technical staff, NIST researchers, DoD program managers, QED-C members.

---

## The Problem (30 Seconds)

Two things are happening simultaneously that most vendors address separately:

1. **Quantum computers threaten existing cryptography.** "Harvest now, decrypt later" attacks are already underway — adversaries are capturing encrypted data today to decrypt when quantum computers mature. Federal agencies must migrate to post-quantum cryptography.

2. **AI agents are executing consequential actions without cryptographic accountability.** Autonomous AI systems are making decisions — allocating resources, controlling infrastructure, authorizing transactions — but their *execution authority* is governed by classical cryptography that a quantum computer could forge.

Every existing PQC solution addresses the first problem. **Nerion addresses both simultaneously, at the execution layer.**

---

## What Nerion Does (2 Minutes)

Nerion is an open-source **post-quantum execution governance protocol**. It cryptographically controls what autonomous AI agents are permitted to do, using NIST-finalized post-quantum standards.

**The analogy:** Two-person integrity rules govern nuclear weapon release authority — no single individual can authorize a launch. Nerion applies the same concept to AI agent actions, enforced by post-quantum signatures that no quantum computer can forge.

**In technical terms:**
- Every AI agent action flows through a stateless deterministic `decide()` function
- `decide()` returns `deny` unless a verifiable post-quantum capability signature authorizes the specific action
- Any exception, unexpected input, or missing capability results in `deny` — fail-closed by design
- Every decision is logged to a tamper-evident Merkle log with inclusion proofs

**What this means for federal systems:**
- An adversary who compromises an AI agent's runtime cannot forge new authorizations — the signatures are PQC (ML-DSA-87, FIPS 204)
- A rogue or hallucinating AI agent cannot exceed its signed authority, even if it controls its own runtime
- Every AI decision is cryptographically attributable, auditable, and tamper-evident

---

## Technical Alignment (1 Minute)

Nerion aligns to both active federal mandates:

| Mandate | Alignment |
|---|---|
| NIST FIPS 203 (ML-KEM-1024) | Key encapsulation for agent session establishment |
| NIST FIPS 204 (ML-DSA-87) | Action authorization signatures |
| NIST FIPS 205 (SLH-DSA) | Long-term root signing |
| CNSA 2.0 symmetric suite | HMAC-SHA-384 + AES-256-GCM |
| NIST AI RMF | Cryptographic enforcement of AI risk controls |
| E.O. 14110 AI Accountability | Non-repudiable audit trail for AI decisions |

**Current state:** 469 automated tests + 23/23 conformance checks. CNSA 2.0 aligned — **not yet FIPS 140-3 certified** (CMVP process to be initiated as federal engagement deepens). Externally **unaudited** — independent audit in procurement. Apache-2.0 open source.

---

## Why TRELYAN / Why Now (30 Seconds)

The June 22, 2026 executive orders created a mandate that no existing product fully addresses: **PQC-governed AI agent execution**. Nerion is the first protocol purpose-built for this intersection.

TRELYAN Inc. is a US corporation, 100% owned by founder Brandon Sellam, a full US resident in New York (US business banking with Mercury). All code is Apache-2.0 open source — fully transparent, no vendor lock-in, no supply-chain opacity.

We are in the research and consortium-engagement phase. We are not seeking a production contract today. We are seeking technical partnership with agencies and research institutions to co-develop the reference architecture for PQC-governed AI systems before the 2027 migration pilot deadline.

---

## What We're Asking (15 Seconds)

- **NIST/NCCoE:** Industry partnership in the PQC Migration Consortium
- **CISA:** Inclusion in the PQC Migration Playbook as a reference implementation
- **AFWERX/DoD:** Phase I SBIR engagement on "PQC governance of autonomous AI agents"
- **Any agency:** A 30-minute technical conversation with your PQC migration team

---

## Key Contacts / Links

- **Protocol:** github.com/brandonjsellam-Releone/NERION (Apache-2.0)
- **Technical documentation:** docs/ASSURANCE.md, docs/THREAT_MODEL.md, docs/STATUS.md
- **Specification:** docs/adr/ (21 Architecture Decision Records)
- **Contact:** Brandon Sellam · brandon.sellam@gmail.com · New York, NY

---

*Nerion is UNAUDITED and pre-FTO. These materials are for research and evaluation purposes. TRELYAN makes no claim of FIPS certification, government approval, or non-infringement.*
