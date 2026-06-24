<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# did:nerion DID Method Specification Outline

**Status:** Design document — NOT a W3C-registered DID method. NOT a W3C conformance claim.
**Date:** 2026-06-24

---

## Abstract

`did:nerion` is a proposed Decentralized Identifier (DID) method for identifying AI agents'
governance authorities in the Nerion protocol. A `did:nerion` DID resolves to a DID Document
describing the public keys and service endpoints associated with a Nerion admission kernel or
governance authority. This enables W3C DID ecosystem integration for Nerion-issued permits
and receipts.

**Note:** `did:nerion` is NOT currently registered in the W3C DID Method Registry. This
document is a design outline, not a specification submission. No W3C conformance claim is
made.

---

## 1. Introduction

### 1.1 Motivation

Nerion PermitTokens and Plane-2 receipts bind authorizations to specific AI agent actions.
For external ecosystem interoperability (W3C Verifiable Credentials, eIDAS-2.0 EUDI wallets,
IETF agent-auth), the issuer of a PermitToken must be identified by a resolvable, portable
identifier. A DID is the appropriate primitive: it is cryptographically verifiable,
decentralized, and not dependent on a central registry.

`did:nerion` specifically identifies a **governance authority** — the entity that operates
an admission kernel and issues PermitTokens. It does NOT identify the AI agent itself (that
is a `did:key` over the agent's ML-DSA-87 key, as described in ADR-0030).

### 1.2 Relationship to did:key

For simple deployments, a `did:key` DID constructed from the admission authority's
ML-DSA-87 public key (see ADR-0030, `buildDidKey`) is sufficient. `did:nerion` is the
richer method for production deployments where:
- The governance authority has multiple keys (rotation, recovery).
- The DID Document needs to declare service endpoints (permit issuance, receipt log).
- The authority participates in a ledger-backed governance registry.

---

## 2. Method Name

The method name is `nerion`.

A `did:nerion` DID has the form:
```
did:nerion:<method-specific-id>
```

---

## 3. Method-Specific Identifier Syntax

The method-specific identifier is a base64url-encoded (no padding) identifier derived from
the governance authority's initial ML-DSA-87 public key, with a version prefix:

```
method-specific-id = "v1:" base64url(SHA3-256(ML-DSA-87-public-key-bytes))
```

Example:
```
did:nerion:v1:3q2_7bD1kLmNpQrSt...
```

**Rationale:** SHA3-256 of the public key is compact (32 bytes), collision-resistant, and
deterministically derivable from the key. The `v1:` prefix enables future version evolution
without ambiguity. The DID is stable across key rotations (the initial key is committed at
DID creation; the DID Document carries the current verification key set).

### 3.1 Key type

`did:nerion` uses ML-DSA-87 (FIPS 204 / NIST Module-Lattice-Based Digital Signature
Standard, security category 5) as the primary verification method key type. This provides
post-quantum security against Cryptanalytically Relevant Quantum Computers (CRQCs).

**Note:** ML-DSA-87 is not yet in the W3C DID specification's registered key type list.
A future registration or extension would be required for full W3C conformance. This
specification treats ML-DSA-87 as a provisional key type using the JSON-LD type
`JsonWebKey2020` with `crv: "ML-DSA-87"` (provisional; not a registered JWK curve).

---

## 4. CRUD Operations

### 4.1 Create

A `did:nerion` DID is created by:
1. Generating an ML-DSA-87 key pair (using Nerion's `crypto/src/sign.ts` ML_DSA_87 scheme
   or any FIPS 204 implementation).
2. Computing the method-specific identifier: `v1:` + base64url(SHA3-256(publicKeyBytes)).
3. Constructing the initial DID Document (see §5).
4. Publishing the DID Document to the chosen ledger or registry (see §6).

The DID is determined solely by the initial public key; no central authority assigns DIDs.

### 4.2 Read (Resolve)

A resolver for `did:nerion` retrieves the DID Document from the backing storage layer (see
§6) keyed by the method-specific identifier. The resolver MUST:
1. Verify the DID Document's integrity via the embedded ML-DSA-87 signature (the DID
   Document MUST be signed by the current active verification key).
2. Return the DID Document if the signature is valid, or a `notFound` / `invalidDid` error
   otherwise.
3. Fail closed on any malformed or unauthenticated document.

### 4.3 Update

A governance authority may rotate its verification key by publishing a new DID Document
signed by the current active verification key. The new document replaces the previous one.
Key rotation MUST NOT change the method-specific identifier (the DID is stable; only the
document changes).

Revoked keys MUST be removed from the `verificationMethod` array and SHOULD be listed in
a `revokedKeys` extension property for audit purposes.

### 4.4 Deactivate

A `did:nerion` DID is deactivated by publishing a final DID Document (signed by the current
active key) with `deactivated: true` in the DID Document metadata. Deactivated DIDs MUST
NOT be used to issue new PermitTokens or receipts.

---

## 5. DID Document Structure

A `did:nerion` DID Document follows the W3C DID Core 1.0 structure:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://nerion.trelyan.com/contexts/did/v1"
  ],
  "id": "did:nerion:v1:<method-specific-id>",
  "verificationMethod": [
    {
      "id": "did:nerion:v1:<msid>#key-0",
      "type": "JsonWebKey2020",
      "controller": "did:nerion:v1:<msid>",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "ML-DSA-87",
        "x": "<base64url(publicKeyBytes)>"
      }
    }
  ],
  "authentication": ["did:nerion:v1:<msid>#key-0"],
  "assertionMethod": ["did:nerion:v1:<msid>#key-0"],
  "service": [
    {
      "id": "did:nerion:v1:<msid>#permit-issuer",
      "type": "NerionPermitIssuer",
      "serviceEndpoint": "https://example.com/nerion/permits"
    },
    {
      "id": "did:nerion:v1:<msid>#receipt-log",
      "type": "NerionReceiptLog",
      "serviceEndpoint": "https://example.com/nerion/receipts"
    }
  ]
}
```

**Notes:**
- `JsonWebKey2020` with `crv: "ML-DSA-87"` is provisional — ML-DSA-87 is not a registered
  JWK curve as of June 2026.
- `NerionPermitIssuer` and `NerionReceiptLog` are provisional service types.
- The DID Document itself MUST be signed (as a COSE_Sign1 with the ML-DSA-87 key) for
  integrity verification during resolution.

---

## 6. Storage and Resolution Infrastructure

`did:nerion` is designed to support multiple backing storage options:

1. **Nerion settlement ledger.** DID Documents stored in the Nerion ledger module
   (`ledger/`), providing a cryptographically verifiable, append-only audit trail.

2. **HTTPS well-known endpoint.** For simple deployments, the DID Document MAY be served
   at `https://<domain>/.well-known/did.json` following the `did:web` convention, with the
   method-specific identifier encoding the domain. This is a transitional option.

3. **IPFS / content-addressed storage.** For fully decentralized deployments, the DID
   Document MAY be stored on IPFS with the CID committed into the method-specific
   identifier. This is a future option; not specified here.

---

## 7. Security Considerations

### 7.1 Key Compromise

If the active ML-DSA-87 signing key is compromised, the governance authority MUST
immediately publish a key rotation (§4.3) signed by the compromised key (if possible) or
invoke a recovery mechanism. All PermitTokens and receipts issued under the compromised
key SHOULD be revoked.

### 7.2 DID Document Integrity

DID Documents MUST be signed by the active verification key. Resolvers MUST verify this
signature before trusting any DID Document content. An unsigned or improperly signed DID
Document MUST be rejected.

### 7.3 Quantum Security

ML-DSA-87 (FIPS 204) provides NIST security category 5 post-quantum security. This is the
same signature scheme used in Nerion's Plane-2 receipts and COSE supply-chain statements.
Classical algorithms (RSA, ECDSA) MUST NOT be used as verification method key types in
`did:nerion` documents.

### 7.4 Method Identifier Stability

The method-specific identifier is derived from the INITIAL public key. Key rotation does
not change the DID. This binds the DID to the governance authority's identity, not to a
specific key.

---

## 8. Privacy Considerations

`did:nerion` DIDs identify governance authorities (admission kernels), not individual users.
PermitToken `credentialSubject` DIDs (`did:key` over the agent's key) identify agent
instances. Care must be taken not to correlate agent DIDs across sessions in ways that
enable re-identification of the human principal behind the agent. Nerion's `counterparty`
field in ActionIntent is explicitly labeled "never re-identified across calls."

---

## 9. Relationship to IETF Agent-Auth

`did:nerion` DIDs are intended to be usable as `iss` values in IETF agent-auth-token
descriptors (draft-klrc-aiagent-auth) and as `issuer` values in W3C VC projections
(ADR-0030). This enables a consistent, resolvable identity for Nerion governance authorities
across the emerging agent-auth standards landscape.

---

## 10. Limitations and Future Work

- `did:nerion` is NOT registered in the W3C DID Method Registry.
- ML-DSA-87 as a JWK key type is provisional (not in the IANA JWK curves registry).
- The method does not yet specify a formal JSON-LD context for `NerionPermitIssuer`,
  `NerionReceiptLog`, or ML-DSA-87 key types.
- Ledger-backed resolution infrastructure is under development.
- No W3C DID Core conformance claim is made.

---

## References

- W3C DID Core 1.0, https://www.w3.org/TR/did-core/
- W3C DID Method Registry, https://www.w3.org/TR/did-extensions-methods/
- ADR-0030 (VC-Projection Implementation), this repo
- ADR-0025 (Standards-Binding Profile), this repo
- FIPS 204 (ML-DSA), NIST 2024
- draft-klrc-aiagent-auth (IETF agent-authorization, working draft)
- did:key method, https://w3c-ccg.github.io/did-method-key/
