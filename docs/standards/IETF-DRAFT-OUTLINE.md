<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# IETF Internet-Draft Outline: Post-Quantum Execution Governance for Autonomous AI Agent Systems

## Strategic Purpose

This outline describes a potential IETF internet-draft submission for the Nerion protocol. An IETF draft would:

- Establish Nerion as an international standard, not just an open-source project
- Create a citable reference for federal procurement conversations
- Attract contributors from the global cryptographic community
- Support the NLnet NGI Restack application (European research dimension)
- Provide RATS WG a concrete AI-agent attestation case study

## Proposed Draft Title

**"Post-Quantum Execution Governance Protocol for Autonomous AI Agent Systems"**

Abbreviated draft name: `draft-sellam-nerion-pq-execution-governance`

## Proposed Working Group

**Primary target: IETF RATS (Remote ATtestation procedureS) WG**

Rationale: Nerion's cryptographic accountability chain maps directly to the RATS architecture defined in RFC 9334. Specifically:

| RATS concept | Nerion mapping |
|---|---|
| Attester | Governance Kernel (decide()) |
| Evidence | ActionManifest + PermitToken |
| Verifier | Receipt verifier / Merkle audit log |
| Relying Party | Downstream agent or orchestrator |
| Endorsement | Policy issuance authority |

The RATS "passport model" (Evidence → Verifier → Attestation Result → Relying Party) is structurally identical to Nerion's permit-decide-receipt flow. This is not a stretch mapping; it is the same architecture applied to AI agent action authorization.

**Fallback: BOF on "AI Agent Authorization"**

If RATS WG determines its charter is too narrow for AI agent actions (vs. hardware attestation), the appropriate path is a BOF (Birds of a Feather) session at IETF 122 or 123 to gauge interest in a new WG. A BOF would be co-anchored by the AI safety and cryptographic communities.

**Secondary coordination: IETF SCITT WG**

The Nerion Merkle log / tamper-evident ledger is structurally compatible with SCITT (Supply Chain Integrity, Transparency and Trust) transparency logs (draft-ietf-scitt-architecture). Cross-referencing SCITT in the draft would be appropriate for the ledger component.

---

## Draft Structure

### 1. Introduction

**Problem statement:** Autonomous AI agents execute actions (API calls, file writes, network requests, financial transactions) with real-world consequences. No existing internet protocol governs *which actions* an agent is authorized to execute at the cryptographic level. Current approaches rely on application-layer access control, which is not attestable, not non-repudiable, and not post-quantum secure.

**"Harvest now, decrypt later" risk for AI execution:** Adversaries who capture agent execution logs today can decrypt authorization tokens in the post-quantum era, retroactively forging or repudiating AI-executed actions. This is the AI-governance analogue of the encrypted-traffic harvest problem that motivates NIST PQC.

**Scope:** This document specifies a protocol for cryptographic execution governance of autonomous AI agent actions. It defines wire formats, cryptographic primitives, conformance requirements, and security properties. It does not govern AI model weights, training data, or inference behavior.

**Design principle (govern the verb, never the eye):** The protocol governs *actions* an agent takes, not observations it makes. Observations (reading data, querying APIs without side effects) are outside scope. This scope limit is intentional and stated in the protocol.

### 2. Terminology

Terms defined in this document, consistent with RFC 2119 and RFC 8174:

| Term | Definition |
|---|---|
| **Action** | A discrete, externally observable operation an AI agent performs with real-world consequences (file write, API call, message send, etc.) |
| **Action Manifest** | A deterministic, dCBOR-encoded data structure describing a proposed action before it is executed, including intent commitment, capability claim, and cryptographic binding |
| **PermitToken** | A signed authorization token issued by the Governance Kernel authorizing a specific Action Manifest for execution |
| **ActionReceipt** | A cryptographically signed record of a completed action, including the original manifest and execution outcome |
| **Governance Kernel** | The deterministic policy engine that evaluates Action Manifests against policy and issues or denies PermitTokens; implements decide() |
| **Intent Commitment** | A salted hash of the action's stated intent, binding the human-readable description to the cryptographic record |
| **Merkle Log** | A tamper-evident append-only log of ActionReceipts from which inclusion proofs can be derived |
| **Fail-Closed** | A property of the Governance Kernel: in the absence of an explicit permit, action execution is denied |
| **Negative Oracle** | The property that the Governance Kernel can deny actions without observing or recording their content (deny without inspect) |
| **SuiteID** | A single-byte identifier for the cryptographic suite in use; `0x01` = Ps1 (production suite) |

### 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         AI Agent                                │
│                                                                  │
│  1. Construct ActionManifest(intent, capability, context)       │
│  2. Call decide(manifest) → PermitToken | Denial                │
│  3. Execute action only if PermitToken received                  │
│  4. Generate ActionReceipt(manifest, permit, outcome)           │
│  5. Append receipt to Merkle log                                 │
└────────────────────────────┬────────────────────────────────────┘
                             │ decide()
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Governance Kernel                             │
│                                                                  │
│  - Evaluate manifest against policy (capability + context)      │
│  - Fail-closed: deny unless explicitly permitted                 │
│  - Sign PermitToken with ML-DSA-87 governance key               │
│  - Return denial with reason code if not permitted               │
└────────────────────────────┬────────────────────────────────────┘
                             │ receipt
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Merkle Log                                  │
│                                                                  │
│  - Append-only, tamper-evident                                   │
│  - SCITT-compatible transparency log                             │
│  - Inclusion proofs for third-party verification                 │
└─────────────────────────────────────────────────────────────────┘
```

The `decide()` function is the protocol's central invariant: it is **deterministic** (same inputs always produce same authorization decision), **stateless** (does not depend on execution history), and **fail-closed** (default is deny).

### 4. Cryptographic Primitives

All primitives are drawn from NIST PQC Final Standards (FIPS 203, 204, 205) and NIST SP 800-series:

| Primitive | Algorithm | Use |
|---|---|---|
| KEM | ML-KEM-1024 (FIPS 203) | PermitToken key encapsulation, per-audience permit keys |
| Signature | ML-DSA-87 (FIPS 204) | Governance Kernel signing of PermitTokens; ActionReceipt signing |
| Hash-based signature | SLH-DSA (FIPS 205) | Long-lived root keys; Merkle log root commitment |
| MAC | HMAC-SHA-384 (FIPS 198-1) | Intent commitment binding; policy integrity |
| AEAD | AES-256-GCM | PermitToken payload encryption |
| KDF | HKDF-SHA-384 | Per-audience key derivation from shared secrets |
| Hash | SHA-384 | Merkle tree nodes; intent salting |

**Security level:** All algorithms target NIST PQC security level 5 (≥ AES-256 security against quantum adversaries). The protocol does not permit downgrade to level 3 or below.

**QROM security note:** ML-DSA-87 and ML-KEM-1024 security proofs hold in the Quantum Random Oracle Model (QROM). This provides stronger assurance than classical ROM proofs for protocol components used in the post-quantum threat model.

**Classical component:** HMAC-SHA-384 provides classical MAC security as a defense-in-depth layer. No classical asymmetric primitives (RSA, ECDSA, ECDH) appear in the protocol.

### 5. Wire Format

All wire-format objects are encoded in **dCBOR** (Deterministic CBOR, per RFC 8949 §4.2 and draft-ietf-cbor-dcbor). Deterministic encoding is required for canonical signing.

#### 5.1 Action Manifest

```
ActionManifest = {
  1: SuiteID,            ; uint8, 0x01 = Ps1
  2: tstr,               ; intent: human-readable action description
  3: bstr,               ; intent_commit: HMAC-SHA-384(salt || intent)
  4: bstr,               ; capability: capability identifier bytes
  5: bstr,               ; context_hash: SHA-384(context_blob)
  6: bstr,               ; nonce: 32-byte random nonce (replay protection)
  7: uint,               ; timestamp: Unix epoch seconds
  ? 8: bstr,             ; audience: optional recipient key identifier
}
```

See ADR-0014 (salted intent commitment) and ADR-0015 (per-audience HKDF permit keys) for the rationale behind fields 3 and 8.

#### 5.2 PermitToken

```
PermitToken = {
  1: SuiteID,            ; uint8, must match manifest SuiteID
  2: bstr,               ; manifest_hash: SHA-384(canonical ActionManifest)
  3: bstr,               ; issued_at: uint timestamp, CBOR-encoded
  4: bstr,               ; expires_at: uint timestamp, CBOR-encoded
  5: bstr,               ; encapsulated_key: ML-KEM-1024 ciphertext
  6: bstr,               ; payload_ct: AES-256-GCM encrypted permit body
  7: bstr,               ; signature: ML-DSA-87 over fields 1-6
}
```

#### 5.3 ActionReceipt

```
ActionReceipt = {
  1: SuiteID,            ; uint8
  2: bstr,               ; manifest_hash: SHA-384(canonical ActionManifest)
  3: bstr,               ; permit_hash: SHA-384(canonical PermitToken)
  4: uint,               ; outcome: 0=success, non-zero=failure code
  5: bstr,               ; executed_at: uint timestamp, CBOR-encoded
  6: bstr,               ; signature: ML-DSA-87 over fields 1-5
}
```

Conformance tests for wire format are maintained in `conformance/` and exercise all 23 conformance cases (C01–C23) defined in the test suite.

### 6. Conformance Requirements

Language per RFC 2119 and RFC 8174.

**Governance Kernel (decide() implementation):**

- MUST reject any ActionManifest with a SuiteID not in the implementation's permitted set.
- MUST verify HMAC-SHA-384 intent commitment before evaluating policy.
- MUST deny any ActionManifest that does not satisfy all applicable capability constraints.
- MUST be fail-closed: absence of an explicit permit MUST produce a denial, not a permit.
- MUST NOT issue a PermitToken with an expiry beyond the policy-configured maximum window.
- MUST sign every issued PermitToken with an ML-DSA-87 key held by the Governance Kernel.
- SHOULD verify the nonce is not a replay of any nonce seen within the anti-replay window.

**ActionReceipt generation:**

- MUST be produced for every action attempted, whether permitted or denied.
- MUST include the SHA-384 hash of the canonical ActionManifest.
- MUST be signed with ML-DSA-87.
- MUST be appended to the Merkle log within the policy-configured deadline.

**Merkle Log:**

- MUST be append-only. Existing entries MUST NOT be modified or deleted.
- MUST support generation of inclusion proofs for any logged receipt.
- SHOULD use SLH-DSA for root commitment signatures on log checkpoints.

**Verifier:**

- MUST verify ML-DSA-87 signatures on PermitTokens and ActionReceipts before accepting them.
- MUST verify that the manifest hash in a PermitToken matches the presented ActionManifest.
- MUST reject PermitTokens with expired timestamps.

### 7. Security Considerations

#### 7.1 Fail-Closed Design

The protocol's primary security property is fail-closed authorization: any failure in manifest parsing, policy evaluation, signature verification, or key availability MUST result in a denial. Implementations MUST NOT default to permit on error.

#### 7.2 Non-Repudiation

Every PermitToken and ActionReceipt carries an ML-DSA-87 signature from a key held by the Governance Kernel. Combined with Merkle log inclusion proofs, this provides cryptographic non-repudiation of AI agent actions: neither the agent nor the governance authority can plausibly deny that a specific action was authorized or executed.

#### 7.3 Replay Protection

The 32-byte nonce in the ActionManifest provides replay protection. Implementations SHOULD maintain an anti-replay cache of seen nonces within a sliding time window. The timestamp field provides a secondary layer: manifests with timestamps outside the acceptable window MUST be rejected.

#### 7.4 Intent Commitment Binding

The HMAC-SHA-384 intent commitment (field 3 of ActionManifest) binds the human-readable intent description to the cryptographic record. The salt prevents pre-computation attacks. This ensures that the signed record reflects the stated intent at the time of authorization, not a post-hoc relabeling.

#### 7.5 QROM Security Notes

ML-DSA-87 and ML-KEM-1024 are proven secure in the Quantum Random Oracle Model. Protocol designers extending this specification SHOULD avoid introducing classical asymmetric components, which would reduce the overall security to classical levels.

#### 7.6 Side-Channel Considerations

Governance Kernel implementations MUST use constant-time comparison for all cryptographic material comparisons (nonces, MACs, hashes). Timing variability in the decide() function could leak policy information. See `docs/SIDE_CHANNEL_AUDIT.md` for the reference implementation's audit findings.

#### 7.7 Key Compromise

Compromise of the Governance Kernel's ML-DSA-87 signing key allows an attacker to forge PermitTokens. Implementations SHOULD use hardware security modules or equivalent key custody (e.g., Azure Key Vault with RSA-4096 KEK wrap) for Governance Kernel keys. Key rotation procedures MUST be defined in deployment policy.

#### 7.8 Negative Oracle Property

The Governance Kernel evaluates policy against the capability identifier and context hash, not the full action content. This means the Kernel can deny an action without reading the action's data payload — the negative oracle property. This limits the Kernel's exposure to sensitive action data.

### 8. IANA Considerations

This document requests the following IANA registrations (subject to Working Group and IESG review):

**Media Types:**

| Media Type | Description |
|---|---|
| `application/nerion-manifest+dcbor` | Nerion Action Manifest |
| `application/nerion-permit+dcbor` | Nerion PermitToken |
| `application/nerion-receipt+dcbor` | Nerion ActionReceipt |

**CBOR Tag:**

A CBOR tag for Nerion protocol objects would be requested from the IANA CBOR Tags registry.

**Algorithm Identifiers:**

References to existing COSE algorithm identifiers for ML-KEM-1024, ML-DSA-87, and SLH-DSA would be cited from the COSE Algorithms registry (per draft-ietf-cose-dilithium, draft-ietf-cose-kyber, etc.).

### 9. References

**Normative References:**

- RFC 2119: Key words for use in RFCs to Indicate Requirement Levels
- RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
- RFC 8949: Concise Binary Object Representation (CBOR)
- RFC 9334: Remote ATtestation procedureS (RATS) Architecture
- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
- FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)
- FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)
- NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: GCM
- NIST SP 800-56C: Recommendation for Key-Derivation Methods in Key-Establishment Schemes (HKDF)

**Informative References:**

- draft-ietf-scitt-architecture: An Architecture for Trustworthy and Transparent Digital Supply Chains
- draft-ietf-cbor-dcbor: Deterministic CBOR (dCBOR)
- draft-ietf-cose-dilithium: ML-DSA for JOSE and COSE
- RFC 9162: Certificate Transparency Version 2.0 (Merkle log reference architecture)
- NIST IR 8547: Transition to Post-Quantum Cryptography Standards

---

## Timeline (if pursued)

| Milestone | Target |
|---|---|
| Individual draft submitted (`-00`) | Month 1 after decision to pursue |
| RATS WG mailing list discussion | Month 2 |
| IETF 122 (Dublin, March 2026) — present to RATS WG | Month 3 |
| Revised draft incorporating WG feedback (`-01`) | Month 4 |
| Working Group adoption decision | Month 6 |
| WGLC (Working Group Last Call) | Month 12 |

**Prerequisites before submission:**

1. NLnet Restack grant application submitted (provides European research credibility)
2. At least one external security review completed (OSTIF or OTF Security Lab)
3. Conformance test suite fully published and linked from draft
4. At least one independent implementation (not TRELYAN) demonstrating interoperability

---

## Notes on Scope and Claims

This outline is a planning document. No claim of IETF Working Group adoption, standardization, or RFC publication is made or implied. IETF standardization is a multi-year community process. The draft described here is an individual submission at the time of first publication.

No FTO (Freedom to Operate) claim, FIPS certification claim, or audit-completion claim is made by this document. See `docs/FTO_TODO.md` and `docs/ASSURANCE.md` for current status of those workstreams.
