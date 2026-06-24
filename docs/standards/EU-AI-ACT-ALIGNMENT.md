<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion EU AI Act Alignment Analysis

## Overview

The EU AI Act (Regulation (EU) 2024/1689) entered into force 1 August 2024. The GPAI provisions apply from 2 August 2025; the high-risk AI system obligations under Annex I–III apply from 2 August 2026. This document maps Nerion's technical properties to the EU AI Act's requirements as relevant to a cryptographic execution-governance protocol.

**Important scope note:** Nerion is a **protocol**, not a deployed AI system. Nerion does not make AI decisions; it governs the actions that AI agents are authorized to take. Deployers who integrate Nerion into a high-risk AI system bear primary EU AI Act compliance obligations under that system's own conformity assessment. This document addresses only the alignment of Nerion's technical properties with the Act's requirements — it is not a declaration of conformity and does not substitute for a deployer's own legal analysis.

---

## Relevant Articles and Alignment Mapping

### Article 9 — Risk Management System

**Regulatory text (summary):** A risk management system shall be implemented throughout the lifecycle of a high-risk AI system, identifying and analyzing known and foreseeable risks, estimating and evaluating risks that may emerge when used as intended, and adopting appropriate risk management measures.

**Nerion alignment:**

The Governance Kernel's fail-closed design directly implements technical risk management at the execution layer. Key properties:

- **Fail-closed authorization:** In the absence of an explicit permit, action execution is denied. This is the technical analogue of the Act's requirement to adopt measures that "minimize risks" — Nerion's default posture is to block, not permit.
- **Negative oracle (govern the verb, never the eye):** The protocol limits governance scope to actions with external consequences, not observations. This bounds the protocol's own risk surface and prevents scope creep into data-visibility governance.
- **Capability-scoped permits:** PermitTokens are scoped to specific capability identifiers. An agent authorized to read files cannot use the same permit to write files. This directly limits action-level blast radius, which is a core risk management requirement.
- **Cryptographic non-repudiation:** Every authorized action is bound to a signed record, enabling post-hoc risk analysis and incident reconstruction.

**Documentation pointer:** `docs/THREAT_MODEL.md` contains the full threat model, identifying adversaries, attack surfaces, and mitigations. This document is the closest Nerion-level equivalent to an Article 9 risk management system documentation.

**Deployer obligation:** Deployers must integrate Nerion's protocol-level risk controls into a broader system-level risk management system that addresses the full AI system lifecycle, including training-time risks, model behavior risks, and deployment-context risks that are outside Nerion's scope.

---

### Article 13 — Transparency and Provision of Information to Deployers

**Regulatory text (summary):** High-risk AI systems shall be designed and developed in such a way as to ensure that their operation is sufficiently transparent to enable deployers to interpret a system's output and use it appropriately.

**Nerion alignment:**

Every AI agent action authorized through the Nerion protocol is bound to a signed `ActionManifest` that is logged to a tamper-evident Merkle log. This creates a machine-verifiable transparency layer for agent execution:

- **Signed ActionManifests:** Each manifest records the stated intent, capability identifier, and context hash at authorization time. The intent is human-readable and committed via HMAC-SHA-384.
- **Intent commitment (ADR-0014):** The salted intent commitment binds the human-readable description to the cryptographic record. Post-hoc relabeling of an action's stated intent is cryptographically infeasible.
- **Merkle log with inclusion proofs:** Every ActionReceipt is appended to a tamper-evident log. Inclusion proofs enable third-party verification that a specific action was authorized and executed, without requiring access to the full log.
- **Non-repudiation:** ML-DSA-87 signatures on PermitTokens and ActionReceipts provide cryptographic non-repudiation — neither the agent nor the Governance Kernel authority can plausibly deny that a specific action occurred.

This transparency infrastructure maps to Article 13's requirement that deployers be able to "interpret" system outputs and "use [the system] appropriately." A deployer using Nerion can audit any action by querying the Merkle log and verifying the inclusion proof.

**Limitation:** Nerion provides transparency of *authorization decisions*, not of model reasoning or inference behavior. The transparency of *why* the model decided to take an action — the upstream reasoning — is outside Nerion's scope and must be addressed by the deployer at the model layer.

---

### Article 14 — Human Oversight

**Regulatory text (summary):** High-risk AI systems shall be designed and developed in such a way, including with appropriate human-machine interface tools, that they can be effectively overseen by natural persons during the period of use.

**Nerion alignment:**

Nerion's protocol infrastructure supports human oversight mechanisms without mandating specific interface implementations:

- **Audit log accessibility:** The Merkle log and inclusion proofs provide the raw material for human oversight interfaces. A human reviewing agent execution can verify, for any action, that it was authorized by a valid PermitToken and that the PermitToken's policy constraints were satisfied.
- **Policy as a human-authored artifact:** PermitTokens are issued against policy defined by human operators. Nerion enforces that policy cryptographically but does not self-modify policy. Human-authored capability constraints remain the authoritative source.
- **Denial reason codes:** When the Governance Kernel denies an action, it returns a reason code. These codes enable human reviewers to understand *why* an action was blocked, supporting oversight of the governance layer itself.

**Limitation:** Nerion does not implement a human oversight interface. Article 14's requirement for human-machine interface tools is a deployer-layer obligation. Nerion provides the underlying cryptographic record from which such interfaces can be built.

---

### Article 15 — Accuracy, Robustness, and Cybersecurity

**Regulatory text (summary):** High-risk AI systems shall be designed and developed in such a way that they achieve, in the light of their intended purpose, an appropriate level of accuracy, robustness, and cybersecurity.

**Nerion alignment:**

The cryptographic design of Nerion directly addresses cybersecurity at the authorization layer:

- **Post-quantum cryptographic primitives:** All asymmetric operations use NIST PQC Final Standard algorithms (ML-KEM-1024, ML-DSA-87, SLH-DSA). This addresses "harvest now, decrypt later" attacks on authorization records — a direct cybersecurity robustness property.
- **Replay protection:** 32-byte nonces in ActionManifests prevent replay attacks on authorization requests.
- **Anti-downgrade:** The SuiteID field enforces cryptographic suite identification. Implementations MUST reject manifests with unrecognized SuiteIDs. There is no downgrade path to classical asymmetric primitives in the Ps1 suite.
- **Fail-closed on error:** Any parsing failure, policy evaluation failure, or signature verification failure produces a denial, not a permit. This prevents error conditions from creating authorization bypasses.

**Gap — FIPS 140-3 CMVP:** The reference implementation has not initiated CMVP validation. For Article 15 cybersecurity claims in federal or high-assurance contexts, CMVP validation of the cryptographic module would strengthen the deployment posture. This remains an open workstream. See `docs/ASSURANCE.md`.

**Gap — external audit:** No external security audit has been contracted as of the date of this document. Two audit threads are submitted (OSTIF + OTF Security Lab #22493) but not yet engaged. The round-1 internal audit (`docs/SECURITY_FINDINGS.md`) has been completed and 4 of 6 HIGH findings addressed.

---

### Article 17 — Quality Management System

**Regulatory text (summary):** Providers of high-risk AI systems shall put a quality management system in place that ensures compliance with this Regulation. The quality management system shall cover all aspects of the provider's activities relevant to the AI system.

**Nerion alignment:**

The Nerion protocol implements cryptographic enforcement of the quality management loop at the execution layer:

```
Policy issuance (permit) → Execution governance (decide) → Receipt (audit) → Log (Merkle)
```

This four-stage cycle is machine-verifiable and tamper-evident:

1. **Policy issuance:** Human operators define capability constraints. The Governance Kernel signs PermitTokens only for manifests that satisfy those constraints.
2. **Execution governance:** The `decide()` function is deterministic and stateless. Given the same inputs, it always produces the same authorization decision — a prerequisite for quality management auditability.
3. **Receipt generation:** Every action (permitted or denied) produces a signed ActionReceipt.
4. **Merkle log:** Receipts are appended to a tamper-evident log, creating a permanent, verifiable quality record.

This is a machine-verifiable quality management chain for the authorization layer. It does not constitute a full Article 17 quality management system — that obligation is a provider-level system encompassing design, development, testing, and post-market monitoring across the full AI system lifecycle.

**Documentation pointer:** `docs/STATUS.md` tracks the current state of the protocol development lifecycle. `CONTRIBUTING.md` and `SECURITY.md` document the project's quality and security disclosure procedures.

---

### Article 26 — Obligations of Deployers

**Regulatory text (summary):** Deployers of high-risk AI systems shall take appropriate technical and organisational measures to ensure they use such systems in accordance with the instructions for use.

**Nerion alignment:**

Nerion provides deployers with the technical infrastructure to document and verify AI agent action authorization. A deployer integrating Nerion can:

- Define capability constraints that reflect the deployer's intended-use policy
- Produce Merkle log inclusion proofs as evidence of compliance with those constraints
- Demonstrate to regulators or auditors that specific actions were or were not authorized

This directly supports Article 26 compliance for the authorization layer. Deployers remain responsible for defining appropriate capability constraints that reflect the system's intended purpose.

---

### Annex IV — Technical Documentation

**Regulatory requirement:** Technical documentation for high-risk AI systems must include: general description of the system, description of development process, information on monitoring and functioning, information on risk management, description of any changes made.

**Nerion alignment:**

The following Nerion documents constitute the protocol-level technical documentation package, analogous to Annex IV requirements for the authorization-layer component:

| Annex IV requirement | Nerion document |
|---|---|
| General system description | `README.md`, `docs/EXECUTIVE_SUMMARY.md` |
| Architecture and design | `docs/adr/` (Architecture Decision Records, ADR-0001 through ADR-0015+) |
| Cryptographic design | `docs/CLEANROOM.md`, `docs/PQC_MIGRATION_ALIGNMENT.md` |
| Threat model and risk assessment | `docs/THREAT_MODEL.md` |
| Security findings and mitigations | `docs/SECURITY_FINDINGS.md`, `docs/SIDE_CHANNEL_AUDIT.md` |
| Assurance and audit status | `docs/ASSURANCE.md`, `docs/AUDIT_PACKAGE.md` |
| Conformance and testing | `conformance/` (23 conformance test cases, C01–C23) |
| Monitoring and operational status | `docs/STATUS.md`, `docs/LAUNCH_READINESS.md` |

Deployers building high-risk AI systems on Nerion should incorporate these documents by reference into their own Annex IV technical documentation package, supplemented with deployer-specific system description, intended purpose, and post-market monitoring procedures.

---

### Recital 12 / Article 5 — Prohibited AI Practices

**Regulatory relevance:** Article 5 prohibits certain AI practices including subliminal manipulation, exploitation of vulnerabilities, social scoring, and real-time biometric surveillance. These prohibitions apply to AI systems, not protocols.

**Nerion position:** The Nerion protocol does not implement any of the Article 5 prohibited practices. The negative oracle property (govern the verb, never the eye) means Nerion explicitly does not govern observations — a design choice that aligns with the Act's concern about surveillance-enabling AI. Nerion has no capability to implement social scoring, biometric surveillance, or manipulation; its scope is limited to authorization of discrete agent actions.

---

## Identified Gaps

The following gaps exist between Nerion's current state and a complete EU AI Act compliance posture for deployers building high-risk AI systems:

| Gap | Status | Path |
|---|---|---|
| Nerion is a protocol, not a deployed system — deployers must add their own EU AI Act compliance layer | Inherent by design | Deployer documentation guidance needed |
| FIPS 140-3 CMVP validation not initiated | Open | Future workstream; relevant for Article 15 cybersecurity claims in high-assurance contexts |
| External security audit not yet contracted | In progress | OSTIF + OTF Security Lab #22493 submitted; awaiting engagement |
| No formal EU conformity assessment or CE marking | Not applicable to protocols | Deployers of high-risk AI systems bear this obligation |
| No post-market monitoring procedure defined at protocol level | Open | Deployer-layer obligation; Nerion can provide Merkle log data as input |
| W3C-VC projection (presentation layer) not yet implemented | Future | Must be presentation-only; MUST NOT alter Nerion signing or verification logic |

---

## NLnet NGI Restack Relevance

The EU AI Act's emphasis on transparency (Article 13), risk management (Article 9), and technical robustness (Article 15) for AI systems maps directly to Nerion's research contributions:

- Nerion proposes a cryptographic, protocol-level solution to AI agent authorization transparency — a problem the Act identifies but does not technically specify.
- The post-quantum cryptographic foundation addresses long-term regulatory durability: authorization records protected by Nerion will remain verifiable and non-repudiable in the post-quantum era.
- The open-source, Apache-2.0 licensed protocol enables European deployers to implement compliant AI agent authorization without vendor lock-in.

These properties support the NLnet NGI Restack application's framing of Nerion as European public digital infrastructure for AI governance.

---

## Disclaimer

This document is an internal technical analysis. It is not legal advice and does not constitute a declaration of conformity under Regulation (EU) 2024/1689. Deployers must obtain their own legal analysis from qualified counsel and conduct their own conformity assessments. No FTO claim, FIPS certification claim, or audit-completion claim is made by this document. See `docs/FTO_TODO.md` and `docs/ASSURANCE.md` for current status.
