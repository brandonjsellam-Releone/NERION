<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# did:nerion DID Method Specification (Draft Outline)

**Status:** DRAFT OUTLINE. Not submitted to the W3C DID Working Group or any registry.
Not a final specification. Provided for design review and community feedback.

---

## Abstract

The `did:nerion` method identifies an AI agent governance authority context - the principal
that holds capability delegation roots within the Nerion protocol. It leverages Nerion Plane-2
receipt chains to bind public keys to authority contexts in a deterministic manner that requires
no mutable registry for read operations. The DID Document can be derived solely from a Nerion
receipt history, making it suitable for offline-first and air-gapped verification.

The `did:nerion` method governs the *authority context* - what actions a governance
principal is authorized to govern - not the personal identity of the agent operator.
This is the "govern the verb, never the eye" principle expressed as a DID.

---

## Nerion DID Syntax

```
did:nerion:<nerion-node-id>:<authority-context-id>
```

Components:

- **nerion-node-id:** `z` + base58btc(SHAKE-256(ML-DSA-87 public key of genesis receipt signer))
  The `z` prefix is the multibase prefix for base58btc encoding.

- **authority-context-id:** `z` + base58btc(SHAKE-256(encodeCanonical(authority-context)))
  where `authority-context` is the canonical CBOR of the allowed verbs and delegation boundary.

Both components use the same base58btc encoding as `did:key` (`z` prefix, multibase base58btc).
The SHAKE-256 output length is 32 bytes (256 bits) for both components.

**Example:**
```
did:nerion:zFp7RKqBt9mXs3nYvW2dJcLe4kUhG8aMpR6xTwQyA1bC:zDr9WnZvQ4kMsXjPt7YeL3gFmRc2nKhB8xV5wTuAiN1E
```

---

## DID Document Structure

The DID Document is deterministically derived from the Nerion Plane-2 receipt chain.
No external mutable registry is required for the Read operation.

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://nerion.dev/vocab/v1"
  ],
  "id": "did:nerion:<nerion-node-id>:<authority-context-id>",
  "verificationMethod": [
    {
      "id": "did:nerion:<nerion-node-id>:<authority-context-id>#key-0",
      "type": "JsonWebKey",
      "controller": "did:nerion:<nerion-node-id>:<authority-context-id>",
      "publicKeyMultibase": "z<base58btc(varint(0xed01) || mldsa87-pubkey)>",
      "comment": "ML-DSA-87 key; multicodec 0xed01 is PROVISIONAL pending final registry assignment"
    }
  ],
  "assertionMethod": [
    "did:nerion:<nerion-node-id>:<authority-context-id>#key-0"
  ],
  "nerionAuthorityContext": {
    "contextDigest": "<authority-context-id>",
    "allowedVerbs": ["finance.transfer.usd", "infra.deploy.k8s"],
    "riskClassCeiling": "T2",
    "currentReceiptHash": "<hex-SHAKE256-of-latest-receipt>",
    "genesisReceiptHash": "<hex-SHAKE256-of-genesis-receipt>"
  }
}
```

The `nerionAuthorityContext` property is an extension and MUST be ignored by resolvers
that do not understand it, per the DID Core specification.

---

## CRUD Operations

### Create

The DID comes into existence when the first Plane-2 receipt is produced that contains:
1. The ML-DSA-87 public key (genesis key).
2. The authority context (allowed verbs, risk ceiling, delegation boundary).
3. A valid ML-DSA-87 signature under the genesis key.

The resolver computes `nerion-node-id` as `z` + base58btc(SHAKE-256(genesis-public-key)) and
`authority-context-id` as `z` + base58btc(SHAKE-256(encodeCanonical(authority-context))).
No registration action is required; the DID is derived deterministically.

### Read

Resolution is deterministic. The resolver:
1. Obtains the receipt chain for the node (from a transparency log, on-chain store, or local
   receipt archive).
2. Verifies each receipt's ML-DSA-87 signature.
3. Assembles the DID Document from the chain's current state (latest active key, latest
   authority context).

No network write is required. A resolver that has access to the receipt chain can resolve
the DID offline.

### Update (Key Rotation)

A new receipt containing:
- The new ML-DSA-87 public key (`rotation-to` field in the receipt).
- A reference to the previous receipt hash (`previous-receipt-hash`).
- A valid signature under the CURRENTLY ACTIVE key.

rotates the authority to the new key. The DID identifier is unchanged (it is derived from
the genesis key); only the active `verificationMethod` changes.

### Deactivate

An explicit revocation receipt (a Plane-2 `SignedEnvelope` with `effect: "revoke"` in the
manifest) marks the authority context as deactivated. After deactivation:
- The DID Document includes `"deactivated": true`.
- No new permits can be issued under this authority context.
- Historical receipts remain valid (they were issued before deactivation).

---

## Security Considerations

### ML-DSA-87 Multicodec Provisional Status

The multicodec code `0xed01` for ML-DSA-87 keys is a community-provisional value. The final
code has not been assigned in the upstream multicodec registry as of June 2026. All DID
identifiers and DID Documents produced using this code MUST be labeled as provisional.
When the canonical code is assigned, a migration receipt (key rotation to the same key, with
updated multicodec encoding) can be issued. This does not change the DID identifier.

### Key Rotation Security

A rotation receipt MUST be signed by the currently active key. Resolvers MUST reject rotation
receipts signed by any key other than the currently active verification method. This prevents
an attacker who obtains a deactivated key from issuing backdated rotation receipts.

### Receipt Chain Ordering

Each receipt includes a `previous-receipt-hash` field (SHAKE-256 of the preceding receipt).
This creates a strictly ordered chain. Resolvers MUST reject receipts with a
`previous-receipt-hash` that does not match the most recently accepted receipt in the chain.

### Replay Protection

PermitTokens issued under a `did:nerion` authority context include a nonce and audience
binding (ADR-0015). Historical permits cannot be replayed; each permit is tied to a specific
action hash and audience key derivation.

### Receipt Chain Availability

The receipt chain is an external dependency of the resolver. The `did:nerion` method does
not specify how the chain is stored. Implementers may use:
- A public transparency log (e.g., a Merkle tree commitment service).
- A distributed ledger.
- A TEE-managed append-only store.
- A local file (for closed-environment deployments).

The choice of storage affects availability guarantees; this is outside the scope of the
DID method itself.

---

## Privacy Considerations

### Authority Context, Not Personal Identity

`did:nerion` identifies a governance authority context, not a natural person. The DID
does not encode any information about the operator of the agent. It is action-scoped
and authority-scoped. This aligns with the Nerion design principle:
"govern the verb, never the eye."

### Correlation Risk

Multiple agents using the same authority context share the same `authority-context-id`
component of the DID. This is intentional for pooled capabilities (e.g., a fleet of agents
operating under the same governance policy). Operators who wish to prevent correlation between
agents must issue separate authority contexts per agent.

### Receipt Chain Linkability

The receipt chain links all actions authorized under a given DID. In deployments where
the receipt chain is public, all governed actions are linkable. Deployments with
confidentiality requirements should use a private receipt store with selective disclosure
(a Phase-B research item).

---

## Conformance

A conforming resolver MUST:
1. Use `encodeCanonical` (deterministic CBOR) for all hashed structures.
2. Use SHAKE-256 (256-bit output) for all component digests.
3. Use base58btc encoding with the `z` multibase prefix.
4. Verify all receipt ML-DSA-87 signatures before constructing the DID Document.
5. Reject receipts with invalid `previous-receipt-hash` references.
6. Treat `nerionAuthorityContext` as an extension (ignore-if-not-understood per DID Core).

A conforming resolver MUST NOT:
1. Use a mutable external registry to resolve or update the DID.
2. Accept rotation receipts signed by non-current keys.
3. Treat deactivated authority contexts as active.

---

## Relationship to did:key and did:web

### did:key

`did:key` is used within the `verificationMethod` of the `did:nerion` DID Document to
express the ML-DSA-87 public key in a self-describing format. The `didKeyFromPublicKey()`
function from `capabilities/src/profile.ts` is the implementation. `did:key` is NOT used
as a replacement for `did:nerion`; it is embedded as the key expression format.

### did:web

`did:web` could serve as an alternative discovery mechanism (via a `.well-known/did.json`
endpoint) to locate a receipt-chain resolver endpoint. The core resolution remains
receipt-chain-based; `did:web` would only provide resolver discovery, not substitute for
it. This integration is optional and deployment-specific.

---

## Open Questions

1. **Optional authority-context-id:** Should `<authority-context-id>` be optional to support
   ephemeral agents that do not need a stable authority context identifier?

2. **DID Document serialization format:** JSON-LD (current outline) vs. CBOR-LD for native
   CBOR environments?

3. **IETF alignment:** How to align the authority context model with the IETF agent-auth-token
   "authorization context" concept to avoid fragmentation?

4. **Threshold ML-DSA:** For multi-agent quorum decisions (ADR-0005), should the genesis key
   be a threshold ML-DSA key? If so, the multicodec encoding needs extension.

5. **Selective disclosure in the receipt chain:** Phase-B research item. How to allow
   a resolver to verify the chain without seeing all governed actions?

---

*(This is a DRAFT OUTLINE. It has not been submitted to any standards body.)*
