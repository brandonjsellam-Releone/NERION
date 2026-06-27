<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 TRELYAN
-->

# Nerion CNSA 2.0 Compliance Map

## Overview

NSA's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) specifies algorithms for
protecting National Security Systems (NSS). This document maps every Nerion cryptographic
operation to CNSA 2.0 requirements and identifies gaps that must be resolved before any
claim of NSS suitability can be made.

> **IMPORTANT DISCLAIMERS (read before proceeding)**
>
> - **UNAUDITED**: Nerion has not been externally audited. Audit inquiries have been
>   submitted to OSTIF and OTF Security Lab (issue #22493). No audit findings have yet
>   been received or addressed.
> - **NOT FIPS 140-3 CERTIFIED**: The CMVP validation process has not been initiated.
>   Module boundary design is pending. No FIPS-validated cryptographic module is in use.
> - **PRE-FTO**: Patent clearance (Freedom-to-Operate) has not yet been obtained.
>   No non-infringement claim is made or implied anywhere in this document.
> - **NOT APPROVED FOR NSS USE**: This document is a planning and alignment reference only.
>   Nerion is not approved, certified, or qualified for use in National Security Systems.
>   Satisfying algorithm alignment does not substitute for FIPS 140-3 validation, supply-chain
>   clearance, or any other NSS accreditation requirement.

---

## 1. Required CNSA 2.0 Algorithms

The table below maps each CNSA 2.0 mandatory algorithm to the corresponding Nerion
implementation and notes the conformance status.

| CNSA 2.0 Requirement | FIPS Standard | Nerion Implementation | Suite | Status | Notes |
|---|---|---|---|---|---|
| Key Establishment: ML-KEM-1024 | FIPS 203 | `ML-KEM-1024` | PS-5 | **ALIGNED** | Nerion Suite PS-5 uses ML-KEM-1024 exclusively for key establishment |
| Digital Signatures: ML-DSA-87 | FIPS 204 | `ML-DSA-87` | PS-5 | **ALIGNED** | Used for all permit / receipt / action-authorization signatures |
| Digital Signatures (long-lived): SLH-DSA-SHAKE-256s | FIPS 205 | `SLH-DSA-SHAKE-256s` | PS-5 | **ALIGNED** | Used for root / anchor signing; stateless hash-based fallback |
| Symmetric Encryption: AES-256 | FIPS 197 | `AES-256-GCM` | PS-5 | **ALIGNED** | All symmetric encryption uses AES-256 in GCM mode (authenticated) |
| Message Integrity: HMAC-SHA-384 | FIPS 198-1 / FIPS 180-4 | `HMAC-SHA-384` | PS-5 | **ALIGNED** | All HMAC operations use SHA-384 |
| Hash: SHA-384 | FIPS 180-4 | `SHA-384` via `HMAC-SHA-384` | PS-5 | **ALIGNED** | No standalone SHA-384 path currently; used exclusively within HMAC |

---

## 2. Non-Conformant Aspects

The following items represent known gaps relative to full CNSA 2.0 / NSS compliance.
Each gap must be remediated before Nerion could be considered for any NSS deployment.

| Item | Status | Remediation Path |
|---|---|---|
| FIPS 140-3 CMVP validation | **NOT INITIATED** | Define module boundary; engage accredited laboratory; submit CMVP package |
| NSS-grade supply-chain assurance | **NOT MET** | Open-source project; no DCSA facility clearance; no government supply-chain vetting |
| SLH-DSA parameter confirmation | **PENDING REVIEW** | Verify that the SLH-DSA instance in PS-5 exactly matches `SLH-DSA-SHAKE-256s` per FIPS 205 §10 |
| Key-derivation function alignment | **PENDING REVIEW** | Confirm HKDF-SHA-384 (used in permit-key derivation, ADR-0015) is the approved KDF for the NSS context |
| Side-channel mitigation evidence | **PARTIAL** | `docs/SIDE_CHANNEL_AUDIT.md` initiated; constant-time enforcement not independently verified |
| Random-number generation | **PENDING** | Confirm DRBG backing `@noble/*` primitives meets SP 800-90A Rev.1 requirements |

---

## 3. CNSA 2.0 Timeline Alignment

CNSA 2.0 defines a mandatory transition timeline for NSS software and firmware:

| NSA Milestone | Target Year | Nerion Status |
|---|---|---|
| Begin PQC transition | 2025 | **COMPLETE** — all new Nerion suites use PQC-only (PS-5) or hybrid (PS-1) |
| No new deployments of classical-only crypto for NSS | 2026 | **ALIGNED** — no classical-only suite exists; PS-1 is hybrid as an interoperability bridge |
| Exclusive PQC for all NSS software | 2030 | **PLANNED** — PS-1 (hybrid) would need to be deprecated; PS-5 would be the sole permitted suite |
| Complete transition for legacy systems | 2033 | **OUT OF SCOPE** — Nerion does not govern legacy systems; responsibility lies with deployers |

---

## 4. Suite Reference: PS-1 vs PS-5

Nerion ships two cryptographic suites. For NSS contexts, only PS-5 is CNSA 2.0 aligned.

### 4.1 Suite PS-1 — Hybrid Classical + Post-Quantum

| Primitive | Algorithm | Purpose |
|---|---|---|
| KEM | X-Wing (X25519 + ML-KEM-768) | Key establishment — hybrid classical/PQ |
| Signature | ML-DSA-87 | Permit / receipt authorization |
| Symmetric | AES-256-GCM | Payload encryption |
| MAC | HMAC-SHA-384 | Intent commitment, HKDF |

**NSS status**: NOT CNSA 2.0 aligned for NSS use. X25519 is a classical elliptic-curve
primitive not listed in CNSA 2.0. PS-1 is provided solely for backward-compatible
interoperability with deployments that cannot yet adopt pure-PQC.

### 4.2 Suite PS-5 — Pure Post-Quantum (CNSA 2.0 Candidate)

| Primitive | Algorithm | FIPS Ref | CNSA 2.0 |
|---|---|---|---|
| KEM | ML-KEM-1024 | FIPS 203 | Required |
| Signature (operational) | ML-DSA-87 | FIPS 204 | Required |
| Signature (long-lived / root) | SLH-DSA-SHAKE-256s | FIPS 205 | Required |
| Symmetric | AES-256-GCM | FIPS 197 | Required |
| MAC / KDF | HMAC-SHA-384 | FIPS 198-1 | Required |

**NSS status**: Algorithm selection is CNSA 2.0 aligned. Subject to all disclaimers in
Section 0 — algorithm alignment alone does not constitute FIPS 140-3 validation or NSS approval.

---

## 5. Operational Mapping by Nerion Subsystem

| Nerion Subsystem | Operation | Algorithm (PS-5) | CNSA 2.0 Alignment |
|---|---|---|---|
| Permit issuance | Issuer signature over permit token | ML-DSA-87 | Aligned |
| Permit verification | Signature verification | ML-DSA-87 | Aligned |
| Per-audience key derivation | HKDF-SHA-384 over permit body | HMAC-SHA-384 | Aligned (pending KDF review) |
| Action-receipt signature | Executor ML-DSA-87 signature | ML-DSA-87 | Aligned |
| Intent commitment | Salted HMAC-SHA-384 (ADR-0014) | HMAC-SHA-384 | Aligned |
| Quorum receipt aggregation | Merkle construction over ML-DSA-87 sigs | SHA-384 / ML-DSA-87 | Aligned |
| Session key establishment | ML-KEM-1024 encapsulation | ML-KEM-1024 | Aligned |
| Payload confidentiality | AES-256-GCM | AES-256-GCM | Aligned |
| Root / anchor signing | SLH-DSA-SHAKE-256s | SLH-DSA-SHAKE-256s | Aligned |
| Azure KEK wrapping | RSA-4096 (Azure Key Vault) | — | **NOT CNSA 2.0** — KEK custody only; RSA not in CNSA 2.0 for NSS |

> **Note on Azure KEK**: The RSA-4096 seal key in Azure Key Vault (`polarseek-seal-kek`) is
> used exclusively as a key-encryption key for local key custody, not for any protocol-level
> cryptographic operation. For an NSS deployment, this KEK would need to be replaced with an
> ML-KEM-1024-based wrapping scheme or a FIPS 140-3 validated HSM supporting PQC.

---

## 6. Relationship to Other Compliance Documents

| Document | Location | Relationship |
|---|---|---|
| Threat Model | `docs/THREAT_MODEL.md` | Adversary assumptions underlying algorithm choices |
| Assurance | `docs/ASSURANCE.md` | Broader security-assurance claims and evidence |
| PQC Migration Alignment | `docs/PQC_MIGRATION_ALIGNMENT.md` | Detailed PQC transition rationale |
| Side-Channel Audit | `docs/SIDE_CHANNEL_AUDIT.md` | Physical / timing attack mitigations |
| Security Findings | `docs/SECURITY_FINDINGS.md` | Known open issues and remediation status |
| ADR-0014 | `docs/adr/ADR-0014.md` | Salted intent commitment (RCPT-001) |
| ADR-0015 | `docs/adr/ADR-0015.md` | Per-audience HKDF permit keys (PERMIT-001) |

---

## 7. Path to Increased NSS Readiness

The following ordered steps would move Nerion toward NSS-deployable status. None of these
steps has been initiated; this list is a planning reference only.

1. **Confirm SLH-DSA parameter match** against FIPS 205 §10 test vectors for `SLH-DSA-SHAKE-256s`.
2. **Validate DRBG** backing `@noble/post-quantum` against SP 800-90A Rev.1 requirements.
3. **Define FIPS 140-3 module boundary** covering PS-5 primitives.
4. **Engage an accredited CMVP laboratory** for FIPS 140-3 testing.
5. **Replace Azure RSA-4096 KEK** with a FIPS 140-3 validated PQC-capable HSM for NSS key custody.
6. **Complete independent side-channel audit** with written findings and remediation evidence.
7. **Obtain FTO opinion** from qualified patent counsel before any government procurement claim.
8. **Complete OSTIF / OTF Security Lab audit** and address all findings.

---

## 8. Document Metadata

| Field | Value |
|---|---|
| Nerion conformance suite at time of writing | C23 (313 tests / 23-of-23 passing) |
| CNSA 2.0 reference | NSA CNSA 2.0 (published September 2022) |
| FIPS references | FIPS 203, 204, 205 (final, 2024); FIPS 197; FIPS 198-1; FIPS 180-4 |
| Last updated | 2026-06-24 |
| Status | Planning reference — NOT a certification claim |
