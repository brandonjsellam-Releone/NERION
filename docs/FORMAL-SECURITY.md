<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion — Formal Security Memo: ML-DSA-87, ROM/QROM Gap Analysis, and Regulatory Alignment

**Status: DESIGN/ANALYSIS ONLY — UNAUDITED internal research memo.** This document records the
PhD Panel's formal security analysis of Nerion's ML-DSA-87 usage, the ROM vs. QROM gap, and
alignment considerations for EU and US AI governance frameworks. **No claim here is audited,
FIPS-validated, legally certified, or a non-infringement statement.** Regulatory alignment
observations are informational only; Nerion is infrastructure / a protocol, not an "AI system"
subject to direct AI Act obligations. Date: 2026-06-24. Panel: Nerion R&D PhD Sprint 1.

---

## 1. ML-DSA-87 Usage Summary

Nerion uses ML-DSA-87 (CRYSTALS-Dilithium, NIST FIPS 204, Security Category 5) as the primary
signing algorithm in:

- `crypto/src/suites.ts` — suite definition and key-generation/sign/verify wrappers
- Receipt signing in `receipts/`, permit token integrity in the Plane-1 HMAC path (ADR-0015),
  CNSA 2.0 alignment verdict oracle signing (ADR-0008), and intent-commitment signing (ADR-0014)

ML-DSA-87 provides NIST Security Level 5 (≥ 256-bit classical and quantum security) under the
lattice-based security assumptions described in FIPS 204 (Module-Lattice-Based Digital Signature
Standard, final 2024).

---

## 2. ROM vs. QROM: What the Security Proof Covers

### 2.1 The ML-DSA security reduction

The ML-DSA security proof reduces unforgeability (EUF-CMA) to the hardness of the Module
Learning With Errors (MLWE) problem and the Module Short Integer Solution (MSIS) problem over a
module lattice with ring `Z_q[X]/(X^256 + 1)`. At the Dilithium3/ML-DSA-65 level and above, the
concrete parameters are chosen so that the best known lattice reduction algorithms (BKZ with
blocksize β) require work ≥ 2^256 under current estimates.

The FIPS 204 security proof uses **two distinct models**:

1. **Random Oracle Model (ROM):** the hash functions `H` (collision-resistant expansion) and `ρ`
   (public-matrix seed expansion) are modelled as ideal random oracles. In this model, ML-DSA is
   provably EUF-CMA-secure under MLWE + MSIS.

2. **Quantum Random Oracle Model (QROM):** quantum adversaries may query the random oracle in
   superposition. The FIPS 204 security argument includes a QROM treatment in the sense that the
   parameters are chosen to resist quantum adversaries; however, **the reduction tightness in the
   QROM is weaker than in the ROM**. Specifically:

   - The QROM reduction for Fiat-Shamir-with-aborts (the Dilithium structure) involves a
     Measure-and-Reprogram (MaR) or One-Way-to-Hiding (O2H) reduction step that incurs a
     polynomial security loss in the number of signing queries `Q_S` and hash queries `Q_H`.
   - The concrete security estimates in FIPS 204 account for this loss in parameter selection,
     but the reduction is **not tight**: the effective quantum security margin is narrower than
     the claimed 256-bit level by a term of order O(log(Q_H + Q_S)).
   - For practical adversary budgets (Q_H, Q_S ≤ 2^64), the margin is not expected to close the
     256-bit gap; however, **this is a heuristic extrapolation**, not a proven bound.

### 2.2 What this means for Nerion

| Question | Answer |
|---|---|
| Is ML-DSA-87 quantum-resistant in the ROM? | Yes — provably EUF-CMA-secure under MLWE + MSIS, assuming the random oracle. |
| Is the QROM reduction tight? | No — there is a O(log Q) security loss; the reduction is not tight. See residual gap below. |
| Does the non-tight QROM reduction affect Nerion today? | No practical impact at current adversary budgets; it is a theoretical gap, not a known attack. |
| Is the hiding of Nerion's ZK proofs PQ-secure? | Yes — Pedersen commitments are perfectly hiding (information-theoretic), independent of ML-DSA. |
| Is the soundness of Nerion's ZK proofs PQ-secure? | **No** — ZK soundness rests on discrete-log hardness (classical assumption). A quantum adversary that can compute discrete logs on ristretto255 could forge range proofs. This is labeled throughout the codebase and docs as a known classical leg. |

### 2.3 Residual formal analysis gaps

**Gap 1 — QROM tightness for ML-DSA-87.**
The Measure-and-Reprogram technique used in the Fiat-Shamir-with-aborts QROM proof (Kiltz,
Lyubashevsky, Schaffner 2018; Liu, Zhandry 2019) introduces a reduction factor of
O(Q_S · Q_H / 2^λ) where λ is the claimed security level. For ML-DSA-87 (λ = 256), this factor
is negligible for any practical Q_S, Q_H. **However:**
- The exact tightness constant from the FIPS 204 proof is not published with sufficient detail
  to permit independent re-verification without reconstructing the full security argument.
- Nerion's use of ML-DSA-87 in composition with SHAKE256 (random oracle) and the HKDF-SHA-384
  permit-key derivation (ADR-0015) has **not been analyzed as a composed system** in the QROM.
  Each primitive is argued individually; the composition is trusted but unproven.

**Gap 2 — ROM assumption for SHAKE256 in ZK transcripts.**
ADR-0017 documents that the Fiat-Shamir transform for Nerion's ZK range proofs is proven
(internally) in the classical ROM only. The corresponding QROM argument — whether the transcript
binding in `statementHash`/`challenge` (zkrange.ts) is sound against a quantum prover querying
SHAKE256 in superposition — is **explicitly unanalyzed and unaudited**. The Unruh transform or
an O2H-based argument would be needed to lift the classical FS proof to the QROM.

**Gap 3 — Composition: ML-DSA-87 over ZK proofs.**
Nerion's receipt structure signs a ZK proof digest (policyProofDigest, ADR-0006) with ML-DSA-87.
The end-to-end security argument — "a receipt signature on a range-proof digest is unforgeable
and the range proof is sound, therefore the receipt certifies the amount is in range" — requires
a **composed security proof** that neither the ML-DSA FIPS 204 spec nor the internal ZK argument
individually covers. In particular, if the ZK proof's soundness is classical (discrete-log), then
the composed guarantee ("amount is in range, and this fact is PQ-signed") is **only as strong as
the classical ZK leg**. The PQ signature wraps a classically-sound statement; the quantum
adversary need only break the ZK soundness, not the signature.

This compositional limitation is already disclosed in the ASSURANCE.md matrix ("ZK soundness is
CLASSICAL") and is the primary driver of the roadmap item to migrate the commitment layer to a
PQ scheme (removing the discrete-log dependency from soundness).

**Gap 4 — Side-channel analysis.**
FIPS 204 specifies ML-DSA-87's algorithm; it does not certify any implementation. The `@noble`
cryptography library used in Nerion's TypeScript reference implementation has not undergone
side-channel analysis specific to Nerion's deployment context. The Rust crate (`rust/`) is in
early development. Neither implementation is FIPS 140-3 validated. Any production deployment
MUST commission an independent side-channel and fault-injection assessment of the signing
implementation.

---

## 3. EU AI Act Alignment Considerations

> **Important framing.** Nerion is infrastructure / a governance protocol, **not an AI system**
> under the EU AI Act (Regulation (EU) 2024/1689). It processes typed intents, not perception or
> inference outputs. The Act's Article 6 high-risk classification and Article 9 risk management
> obligations apply to AI systems, not to cryptographic governance middleware. The observations
> below are informational, intended to help operators of AI systems that integrate Nerion
> understand how Nerion supports (not substitutes for) their AI Act compliance obligations.

### 3.1 Article 9 — Risk Management System

Art. 9 requires high-risk AI system operators to maintain a documented risk management system
including identification, estimation, and mitigation of risks. For an operator using Nerion to
govern AI action outputs:

| Art. 9 requirement | How Nerion supports (not satisfies) it |
|---|---|
| Identification of risks from the AI system | Nerion's transparency log (RFC 6962/SCITT-style) provides an append-only, tamper-evident record of every admission decision, supporting post-hoc risk identification. |
| Risk mitigation measures | Nerion's kernel enforces fail-closed default-deny admission; ML-DSA-87 signatures provide PQ-resistant evidence of authorization decisions. |
| Residual risks documentation | The ASSURANCE.md matrix and this memo document residual gaps (QROM non-tightness, classical ZK soundness, no FIPS validation). Operators must supplement with their own residual-risk documentation. |
| Lifecycle monitoring | The transparency log enables audit trails but does **not** automatically satisfy ongoing monitoring obligations. |

**Gap:** Nerion does not itself perform risk assessment on AI system outputs. It governs whether
an *action* was authorized; it does not assess whether the underlying AI decision was safe or
appropriate. The Art. 9 risk management obligation for the AI system's outputs rests with the
operator.

### 3.2 Article 15 — Accuracy, Robustness, and Cybersecurity

Art. 15 requires high-risk AI systems to achieve appropriate levels of accuracy and to be robust
against adversarial attacks, errors, and inconsistencies.

| Art. 15 aspect | Nerion's contribution |
|---|---|
| Robustness of authorization decisions | Fail-closed kernel (C8), equivocation slashing (ledger), quorum threshold (C12). |
| Cybersecurity (quantum-resistant signing) | ML-DSA-87 (FIPS 204 Cat. 5) for all authorization signatures; ML-KEM-1024 for key encapsulation. |
| Accuracy | Not applicable — Nerion is a governance layer, not an inference system. Admission decisions are deterministic given inputs. |
| Adversarial robustness of the governance layer | The govern-the-verb negative oracle (C14) tests injection resistance. UNAUDITED ZK proofs (ADR-0006/0016/0017) are not yet independently verified. |

**Gap:** The FIPS 204 implementation used in Nerion has not been evaluated by an accredited
laboratory (FIPS 140-3 CMVP). Operators of regulated AI systems may need CMVP-validated
cryptographic modules, which Nerion does not currently provide.

---

## 4. NIST AI RMF Alignment Considerations

The NIST AI Risk Management Framework (AI RMF 1.0, January 2023) organizes AI risk management
into four functions: GOVERN, MAP, MEASURE, MANAGE. The following maps Nerion's documented
properties to the RMF framework.

### 4.1 GOVERN

GOVERN establishes organizational practices for accountability and risk culture.

| GOVERN aspect | Nerion property |
|---|---|
| G1 — Policies and accountability | Apache-2.0 open-source; CONTRIBUTING.md, SECURITY.md, and disclosure policy documented. |
| G2 — Transparency | Every admission decision is logged (transparency log, C10); ASSURANCE.md provides radical honesty about what is and is not proven. |
| G6 — Responsible deployment | LAUNCH_READINESS.md documents four external gates before production use; repo explicitly labeled pre-production / Local maturity. |
| **Gap** | No organizational AI governance policy exists for Nerion as a component of a deployed system. Operators must establish their own. |

### 4.2 MAP

MAP identifies and characterizes AI risks in context.

| MAP aspect | Nerion property |
|---|---|
| M1 — Context / impact characterization | THREAT_MODEL.md documents adversary classes, trust boundaries, and out-of-scope threats. DESIGN_AROUND.md documents the FTO engineering intent. |
| M3 — Risk tolerance | ASSURANCE.md explicitly documents residual risks and evidence tiers. No audit exists yet. |
| **Gap** | Third-party / supply-chain AI risk (e.g., AI systems that produce intents Nerion governs) is not mapped in Nerion's own documentation; this is the deploying operator's responsibility. |

### 4.3 MEASURE

MEASURE uses quantitative and qualitative methods to analyze AI risks.

| MEASURE aspect | Nerion property |
|---|---|
| M2 — Quantitative testing | 469 automated tests (npm run gate), 23/23 conformance checks. Property-based testing for capability attenuation and quorum receipts. |
| M2.5 — Bias / fairness | Not applicable to a cryptographic governance protocol. |
| M4 — Residual risk tracking | SECURITY_FINDINGS.md, APEX_SPRINT_LOG.md, APEX_SPRINT_BACKLOG.md track known issues and their resolution status. |
| **Gap** | No fuzzing, formal verification, or differential testing against an independent implementation. The ASSURANCE.md "conformance-checked" tier explicitly states it is not external security validation. |

### 4.4 MANAGE

MANAGE treats, monitors, and responds to AI risks.

| MANAGE aspect | Nerion property |
|---|---|
| MN1 — Response plan | SECURITY.md responsible-disclosure policy; CONTRIBUTING.md patch process. |
| MN2 — Incident tracking | APEX_SPRINT_LOG.md tracks findings and fixes (e.g., ZKRANGE-002, RCPT-001, CB-001, PERMIT-001). |
| MN4 — Metrics | Conformance count (23/23) and test count (469) provide basic metrics; no SLO or MTTR defined. |
| **Gap** | No automated vulnerability scanning, no supply-chain SBOM beyond the CBOM (ADR-0009), no incident response SLA. These are pre-production gaps appropriate to the current maturity level. |

---

## 5. Consolidated Residual Gap Table

| Gap ID | Description | Severity | Status |
|---|---|---|---|
| FSG-001 | QROM reduction for ML-DSA-87 is non-tight (O(log Q) loss); composed QROM analysis of ML-DSA + SHAKE256 + HKDF-SHA-384 does not exist. | Low (no known attack) | Open — to be addressed in external audit |
| FSG-002 | ZK range proof soundness (ADR-0017) is proven classical/ROM only; QROM lift not analyzed; a quantum discrete-log adversary could forge proofs. | Medium (known architectural classical leg) | Open — roadmap: PQ commitment migration |
| FSG-003 | Composition of PQ signature (ML-DSA-87) over classical ZK proof digest is not proven as a composed system; overall guarantee is only as strong as the classical ZK leg. | Medium (disclosed; architectural) | Open — resolved by PQ commitment migration |
| FSG-004 | Side-channel / fault-injection analysis of ML-DSA-87 implementation (@noble/post-quantum, Rust crate) not performed. | High for production | Open — pre-production; required before any regulated deployment |
| FSG-005 | No FIPS 140-3 CMVP validation of the ML-DSA-87 implementation; operators in regulated environments may require it. | Deployment-dependent | Open — not planned until production milestone |
| FSG-006 | H provenance in Pedersen commitments (ADR-0016): dlog_G(H) unknownness is a ROM heuristic, not a QROM proof; quantum discrete-log breaks binding. | Medium (same as classical ZK leg) | Open — inherent to the current commitment scheme |
| FSG-007 | EU AI Act Art. 9/15 compliance rests with operators of AI systems that use Nerion; Nerion provides supporting tooling but is not itself compliant or regulated. | N/A for Nerion directly | Documented — operator obligation |

---

## 6. Recommendations

1. **Prioritize external ZK/crypto audit** (OSTIF + OTF Security Lab #22493 pending): the audit
   should explicitly scope the ROM→QROM gap for the Fiat-Shamir range proof (FSG-002) and the
   composed ML-DSA + ZK system (FSG-003). Request that the auditors apply an O2H or Unruh-style
   argument to assess whether the QROM is tractable for the current construction or whether a
   redesign is required.

2. **Document the ML-DSA-87 QROM security loss concretely.** Reproduce the key step of the FIPS
   204 QROM argument and compute the concrete security margin for Nerion's expected signing
   query volume (Q_S ≤ 2^32, Q_H ≤ 2^64). If the margin exceeds 200 bits after the loss term,
   FSG-001 can be downgraded to informational.

3. **Accelerate PQ commitment migration** (roadmap item). Replacing the discrete-log Pedersen
   commitment with a lattice-based or hash-based commitment scheme (e.g., the Ajtai commitment
   or BDLOP-style commitments over the same module lattice as ML-DSA-87) would close FSG-002,
   FSG-003, and FSG-006 simultaneously, making the full stack PQ-sound, not just PQ-signed.

4. **Add explicit QROM gap disclosure to ASSURANCE.md.** The current matrix notes "soundness is
   classical/ROM, not QROM" for ZK rows. It should add a note to the ML-DSA-87 row that the QROM
   reduction is non-tight and that the composed system analysis is absent.

5. **Communicate to operators** that Nerion's EU AI Act / NIST AI RMF mapping is informational
   infrastructure support, not compliance coverage; operators integrating Nerion into high-risk
   AI systems must conduct their own Art. 9 risk assessments and Art. 15 robustness evaluations.

---

## References

- NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium final standard, 2024)
- Kiltz, Lyubashevsky, Schaffner — "A Concrete Treatment of Fiat-Shamir Signatures in the
  Quantum Random Oracle Model" (EUROCRYPT 2018) — the QROM tightness analysis for FS-with-aborts
- Liu, Zhandry — "Revisiting Post-Quantum Fiat-Shamir" (CRYPTO 2019) — improved MaR technique
- NIST AI RMF 1.0 (January 2023), NIST AI 100-1
- EU AI Act (Regulation (EU) 2024/1689), Articles 6, 9, 15
- `docs/ASSURANCE.md` — evidence-tier matrix; authoritative source for claim levels
- `docs/STATUS.md` — UNAUDITED protocol status; pre-production / pre-FTO framing
- `docs/adr/ADR-0016-pin-pedersen-generator-h.md` — H provenance + NUMS argument
- `docs/adr/ADR-0017-orproof-soundness-argument.md` — ZK transcript soundness argument
- `docs/adr/ADR-0001-crypto-suite.md` — ML-DSA-87 suite definition
