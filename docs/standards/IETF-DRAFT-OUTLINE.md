<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# IETF Internet-Draft Outline: Post-Quantum Execution Governance for AI Agent Systems

**Document type:** Strategic planning document — NOT a submission-ready IETF internet-draft.
**Date:** 2026-06-24
**Project:** Nerion / TRELYAN

---

## Abstract

This document outlines a proposed IETF internet-draft covering a post-quantum (PQ) execution
governance protocol for AI agent systems. The core contribution is the "govern the verb"
model: cryptographic binding of an AI agent's authorization to a specific, typed action
(the "verb"), not to a broad capability claim. This approach addresses the dual mandate of
the June 2026 US Executive Orders on AI and the EU AI Act — simultaneously satisfying PQC
migration requirements and AI transparency/governance obligations.

The key technical contribution is a permit token construction that binds authorization to a
canonically encoded action intent via HMAC-SHA-384 (Plane-1 hot path) and ML-DSA-87
(Plane-2 nearline receipts), with per-audience key derivation (HKDF-SHA-384) preventing
cross-audience token forgery. This draft proposes this construction as an open, interoperable
baseline for AI agent authorization in the emerging agent-auth landscape.

---

## 1. Introduction

### 1.1 Problem Statement

Current AI agent authorization relies on OAuth 2.0 and classical JWT-based credentials.
These are inadequate for two converging reasons:

1. **Cryptographic obsolescence.** RSA and ECDSA are vulnerable to Cryptanalytically Relevant
   Quantum Computers (CRQCs). NIST FIPS 203/204 (ML-KEM, ML-DSA) and CNSA 2.0 mandate PQ
   migration. Agent authorization infrastructure built today on classical algorithms will
   require replacement.

2. **Authorization granularity.** Classical agent-auth standards (OAuth scopes, API keys)
   authorize agents to a capability class, not to a specific action instance. An agent
   authorized for "payment:write" can initiate any payment within that scope; the
   authorization is not bound to the exact action proposed. This is insufficient for
   high-risk AI actions (financial, infrastructure, medical) where auditability and
   containment of the authorization to the exact intended action are required.

### 1.2 Motivation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in
all capitals, as shown here.

### 1.3 Scope

This draft covers:
- A post-quantum permit token construction for AI agent execution governance.
- A three-plane architecture separating hot-path authorization from nearline receipts
  and offline settlement.
- Mapping to W3C Verifiable Credentials and DID-based agent identity.
- Security considerations specific to AI agent deployment.

This draft does NOT cover:
- General AI safety or alignment.
- Regulatory conformity claims.
- Key management infrastructure (covered in companion documents).

---

## 2. Terminology

**Action Intent.** A canonical, typed description of the specific action an AI agent proposes
to execute. Consists of: action type (verb), resource identifier, optional counterparty,
optional amount (integer minor units), and optional parameters.

**Admit.** The kernel decision to authorize a specific Action Intent. Admission is always
against the exact Action Intent; it is not a blanket capability grant.

**Permit Token.** A short-lived, MAC'd token binding a kernel admission decision to a
specific Action Intent, audience (resource endpoint), and session. The MAC prevents forgery;
the action hash (SHAKE256 of the canonical Action Intent) prevents substitution.

**Verb.** The action type field of an Action Intent. "Govern the verb" means that all
cryptographic binding, auditability, and governance is scoped to the specific verb proposed,
not to a broad capability class.

**PQ.** Post-quantum; algorithms believed secure against both classical and quantum adversaries.

---

## 3. Protocol Overview

### 3.1 Three-Plane Architecture

The protocol separates concerns across three planes:

**Plane 1 (Hot path).** Sub-millisecond permit issuance and verification. Uses HMAC-SHA-384
with a per-session, per-audience key derived via HKDF-SHA-384. No PQ signature on the hot
path — the HMAC tag is the authorization binding.

**Plane 2 (Nearline receipts).** PQ-signed (ML-DSA-87) receipts recording admission
decisions. Plane-2 receipts are not on the critical path of action execution but MUST be
issued for all Tier 1+ actions. Receipts commit the Action Intent hash, the permit token
suite, and the kernel decision (effect: allow | transform).

**Plane 3 (Settlement/ledger).** Offline settlement and aggregate audit. Not covered in
this draft.

### 3.2 Permit Token Construction

A Permit Token is a three-field structure:

```
PermitToken {
  suite:  SuiteID string  (e.g. "PS-1")
  body:   canonical CBOR encoding of PermitClaims
  mac:    HMAC-SHA-384(audienceKey, toBeMaced(suite, body))
}
```

where `toBeMaced` is the canonical CBOR of `[PERMIT_CONTEXT, suite, body]` with a fixed
domain separator `PERMIT_CONTEXT = "PolarSeek-Permit-v1"`.

The `audienceKey` MUST be derived as:
```
audienceKey = HKDF-SHA-384(sessionKey, salt=empty, info=encodeCanonical([AUDIENCE_KDF_CONTEXT, audience]))
```
where `AUDIENCE_KDF_CONTEXT = "PolarSeek-Permit-AudienceKDF-v1"`.

This derivation ensures that a resource endpoint provisioned only with its `audienceKey`
cannot derive the session key or any sibling audience's key.

### 3.3 Action Hash Binding

The Permit Token's `body` MUST include an `actionHash` field equal to:
```
actionHash = SHAKE256(canonical_CBOR(ActionIntent))
```

A resource verifying the permit MUST recompute this hash from the presented Action Intent
and compare it against the `actionHash` claim. A mismatch MUST cause rejection.

### 3.4 Suite Agility

All Permit Tokens carry a SuiteID. The suite determines the MAC algorithm (currently
HMAC-SHA-384 for both active suites PS-1 and PS-5) and the signature scheme for Plane-2
receipts (ML-DSA-87). A relying party MUST reject tokens whose suite is not in its
allowlist.

---

## 4. Security Considerations

### 4.1 Replay Prevention

A Permit Token is short-lived (RECOMMENDED expiry: 300 seconds). The `audience` field and
`audienceKey` MAC binding prevent replay at a different resource. The `actionHash` binding
prevents replay for a different action. Single-use within the window is the resource's
idempotency responsibility.

### 4.2 Cross-Audience Forgery

The per-audience key derivation (Section 3.2) ensures that a resource cannot forge a
permit for a different audience even if it possesses its own `audienceKey`.

### 4.3 Downgrade Resistance

Suite negotiation transcripts SHOULD be signed and committed. The `SuiteID` is bound into
the MAC/signature transcript so a downgrade to a weaker suite changes the authenticated
bytes and fails verification.

### 4.4 Semantic Laundering

Action types MUST be drawn from a versioned, governed namespace (e.g. `payment.transfer/v1`).
Free-text action types MUST NOT be used. The `policyHash` field in the Action Manifest
(Section 5) further binds the authorization to a specific policy version.

### 4.5 Post-Quantum Security

Plane-2 receipts use ML-DSA-87 (FIPS 204), a NIST-standardized lattice-based signature
scheme believed secure against CRQCs. Plane-1 HMAC-SHA-384 relies on the pre-image
resistance of SHA-384, which is generally considered quantum-resistant for its 192-bit
security level under Grover's algorithm.

---

## 5. Action Manifest (Extension)

An Action Manifest is a structured, canonical CBOR object that can be committed into
Permit Tokens and Plane-2 receipts to make the authorization fully self-describing:

```
ActionManifest {
  verb:            action type string
  authorityScope:  string (capability grant ID)
  preconditions:   array of precondition descriptors
  expectedEffects: array of expected effect descriptors
  riskClass:       integer (0-3)
  policyHash:      hex string (SHA3-256 of policy document)
  provenance:      { tool, model, software }
  replayDomain:    string
  expiry:          integer (unix seconds)
}
```

The Action Manifest digest (SHA3-256 of its canonical CBOR encoding) SHOULD be included in
Plane-2 receipts as defense against semantic laundering.

---

## 6. W3C VC and DID Integration

Permit Tokens MAY be projected into W3C Verifiable Credentials (VC Data Model 1.1) for
external ecosystem interoperability (eIDAS-2.0, EUDI wallets, IETF agent-auth). This
projection is purely a presentation layer — it MUST NOT alter the Permit Token's MAC or
body encoding.

Agent identity SHOULD be expressed as a `did:key` DID over ML-DSA-87. Note that ML-DSA-87
is not yet in the canonical multicodec registry as of June 2026; use of 0xed01 as the
multicodec prefix is provisional.

---

## 7. IANA Considerations

This document would request registration of:
- A new CBOR tag for Nerion Permit Tokens.
- A new media type `application/nerion-permit+cbor`.
- A new COSE algorithm code point for HMAC-SHA-384 in the Nerion context (if not already
  covered by existing COSE MAC registrations).

---

## 8. References

### 8.1 Normative References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels",
  BCP 14, RFC 2119, March 1997.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words",
  BCP 14, RFC 8174, May 2017.
- [RFC5869] Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation
  Function (HKDF)", RFC 5869, May 2010.
- [FIPS203] NIST, "Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)",
  FIPS 203, 2024.
- [FIPS204] NIST, "Module-Lattice-Based Digital Signature Standard (ML-DSA)",
  FIPS 204, 2024.

### 8.2 Informative References

- draft-irtf-cfrg-ml-dsa — ML-DSA IRTF CFRG specification (working draft).
- draft-connolly-cfrg-xwing-kem — X-Wing hybrid KEM (working draft).
- draft-klrc-aiagent-auth — AI agent authorization framework (working draft).
- W3C VC Data Model 1.1, https://www.w3.org/TR/vc-data-model/
- W3C DID Core 1.0, https://www.w3.org/TR/did-core/
- EUDI ARF v1.4, https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework
- CNSA 2.0, NSA, "Commercial National Security Algorithm Suite 2.0", September 2022.

---

*This document is a strategic planning artifact. It is NOT an IETF submission, NOT an
IETF working group document, and NOT a standards-track document. No IETF IPR claims are
made. No FIPS conformance is claimed.*
