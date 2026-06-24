<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# EU AI Act Technical Alignment - Nerion Protocol

**Document type:** Technical alignment analysis. NOT legal advice. NOT a regulatory
compliance certification. Nerion is a protocol component; deployers are responsible for
their own conformity assessments under the EU AI Act.

---

## Disclaimer

This document maps Nerion technical properties to selected provisions of Regulation
(EU) 2024/1689 (the EU AI Act) and Regulation (EU) 2024/1183 (eIDAS-2.0). It is:
- A technical analysis, not a legal opinion.
- A planning document for standards positioning, not a conformity declaration.
- Not a claim that Nerion constitutes a "compliant AI system" under any regulatory framework.

The EU AI Act applies to AI systems holistically - including training data, model behaviour,
human oversight mechanisms, and deployment context. Nerion governs the action layer of an AI
agent. It is a component, not a complete compliance solution.

---

## Article 13 - Transparency and Provision of Information to Deployers

**Regulatory requirement:** High-risk AI systems must be designed and developed to ensure
their operation is sufficiently transparent to enable deployers to interpret the output.

**Nerion mapping:**

| Article 13 element | Nerion mechanism |
|---|---|
| Declaration of intended purpose | `ActionManifest.verbId` - namespaced, machine-readable declaration of the exact action (e.g., `finance.transfer.usd`). Free-text rejected. |
| Risk level transparency | `ActionManifest.riskClass` (T0-T3) - typed risk classification bound into the permit and receipt digest. |
| Policy basis | `ActionManifest.policyHash` - cryptographic digest of the authorizing policy document. |
| Expected output declaration | `ActionManifest.expectedEffects` - declares intended effects before execution. |
| Provenance | `ActionManifest.provenance` (`tool`, `model`, `software`) - origin without PII. |
| Machine-readable format | W3C VC 2.0 projection (`toVerifiableCredential`) - standard credential object for compliance dashboards. |

**Limitation:** Nerion covers the action authorization layer only. It does not provide
transparency into model reasoning, training data, or output generation processes.

---

## Article 17 - Quality Management System

**Regulatory requirement:** Providers must put in place a QMS covering design, development,
testing, validation, and change management.

**Nerion mapping:**

| Article 17(1) element | Nerion mechanism |
|---|---|
| Strategy for regulatory compliance | ADR-0025/0030/0031 - documented architecture decision records. |
| Design and development techniques | Three-plane architecture with formal typed invariants. |
| Verification and validation | SLSA Level 3 provenance (A35 / ci-slsa.yml) - cryptographic proof of the build process. |
| Supply-chain transparency | CycloneDX SBOM (A32 / ci-sbom.yml) - machine-readable component inventory. |
| Data management / audit trail | Capability chain creates an immutable, auditable authorization trail. |
| Recordkeeping | Plane-2 ML-DSA-87 receipts - quantum-safe signed records of every authorized action. |

**Limitation:** A full Article 17 QMS requires documented organizational procedures and
human oversight mechanisms beyond what a protocol library provides.

---

## Annex IV - Technical Documentation

**Regulatory requirement:** Technical documentation must include general description,
design elements, testing procedures, and list of applied standards.

**Nerion mapping:**

| Annex IV element | Nerion mechanism |
|---|---|
| General description | docs/EXECUTIVE_SUMMARY.md, docs/DEPLOY.md, three-plane architecture. |
| Design specifications | ADR-0001 through ADR-0031 - complete architecture decision records. |
| Testing procedures | conformance/vectors/ps-*.json KAT vectors; `npm run conformance` (23-of-23 passing). |
| Applied standards | FIPS 204 (ML-DSA), FIPS 203 (ML-KEM), NSA CNSA 2.0, RFC 5869 (HKDF), FIPS 202 (SHA3). |
| Build process integrity | SLSA Level 3 attestation (A35). |
| Component inventory | CycloneDX SBOM (A32). |

---

## Article 9 - Risk Management System

**Regulatory requirement:** A risk management system must identify, analyze, and estimate
risks that may emerge when the AI system is used.

**Nerion mapping:**

| Article 9 element | Nerion mechanism |
|---|---|
| Risk identification | `RiskTier` (0-3) on every capability grant and permit. |
| Risk quantification | `CapabilityGrant.perActionCeiling` and `aggregateCap` - explicit integer exposure ceilings. |
| Temporal risk bounding | `PermitToken.exp` - hard expiry; non-finite values rejected (fail-closed). |
| Audience isolation | Per-audience HKDF key derivation (ADR-0015). |
| Default-deny authorization | `CapabilityGrant.actions` is an explicit allowlist; no wildcard authority. |
| Residual risk documentation | docs/THREAT_MODEL.md. |

---

## Article 16 - Event Logging

**Relevant element (Article 16(d)):** Automatic recording of events throughout the
AI system lifetime.

**Nerion mapping:** Every Plane-2 receipt is a tamper-evident, ML-DSA-87 signed record.
The receipt chain is an automatic event log that cannot be retroactively forged.

---

## Gaps and Limitations

| Gap | Nature |
|---|---|
| Model output layer | Nerion governs action authorization, not model reasoning or output. |
| Human oversight (Article 14) | Nerion can support human-in-the-loop but does not mandate oversight interfaces. |
| Fundamental rights impact assessment (Article 27) | Not addressed. |
| EU-accredited trust service | Phase-A VC projection is unsigned; a QEAA requires a qualified trust service. |
| Conformity assessment (Article 43) | Deployer/provider obligation; Nerion supports but does not substitute. |
| ML-DSA-87 multicodec provisional | May require additional justification until upstream code is finalized. |

---

## Notes on eIDAS-2.0 Intersection

eIDAS-2.0 mandates W3C VC 2.0 for EUDI wallets. Nerion produces a VC-compatible data
object containing ActionManifest, manifest digest, issuer DID, and subject DID.

The relationship:
1. Phase-A output is an **unsigned VC data object** - not a qualified electronic attestation.
2. A qualified presentation requires wrapping in an eIDAS-qualified trust service signature.
3. The manifest digest bridges Nerion's trust model and the eIDAS trust model for parties
   holding the authority public key.

Nerion is a **bridge component**, not a complete eIDAS solution.
