# ADR-0030: Standards-Binding Profile Phase-A Implementation

<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

## Status

**Accepted — Phase-A implemented.** Additive presentation layer only.
UNAUDITED. Pre-FTO. No legal conformity claim is made. Phase-B (ZK
delegation-chain attenuation) remains gated and unimplemented.

## Context

ADR-0025 (standards-binding profile) defined a three-layer design:

- **(1) Action Manifest** — dCBOR canonical schema committed into the
  PermitToken/receipt digest.
- **(2) Credential / identity binding** — W3C-VC 2.x, eIDAS-2.0 / EUDI-VC, and
  IETF agent-auth-token projections of the existing PermitToken; PQ DID
  (`did:key` over ML-DSA-87 / SLH-DSA).
- **(3) ZK delegation-chain attenuation** — gated research-bet, Phase-B, not
  this ADR.

This ADR records the concrete Phase-A implementation decisions: which fields map
to which standard, what the projection module does, and what it explicitly must
NOT do.

## Decision

### Scope

Phase-A introduces a single new module:

```
planes/src/vc-projection.ts
```

It is a **pure presentation-layer adapter**. It reads an already-issued,
already-verified `PermitToken` (plus its decoded `PermitClaims`) and re-encodes
the same semantic content into the envelope format required by the target
standard. It does not:

- issue or verify any MAC or signature;
- read or derive any key material;
- alter any field of `PermitClaims`;
- touch `PermitToken.body`, `PermitToken.mac`, or `PermitToken.suite`;
- reference `SuiteID Ps1` or the `ps-*.json` KAT vectors;
- add a new call to `issuePermit`, `verifyPermit`, `issuePermit`, or
  `deriveAudiencePermitKey`.

### ActionManifest type

A typed overlay on `ActionIntent` that adds governance fields required for
audit-legible verbs (semantic-laundering defense, council R1):

```
verbId        string   — fully-qualified verb (e.g. 'nerion:payment.transfer:v1')
policyHash    string   — hex of the policy document digest
riskClass     string   — one of 'low' | 'medium' | 'high' | 'critical'
authorityScope string  — the audience / resource scope
expectedEffects string[] — e.g. ['allow', 'audit-log']
preconditions  string[] — opaque policy precondition ids (optional)
provenance     { tool, model, software } — origin metadata (no PII)
replayDomain  string   — e.g. 'session:<sessionId>'
expiry        number   — mirrors PermitClaims.exp (unix seconds)
```

### W3C-VC 2.x projection

The `PermitToken` maps to a W3C Verifiable Credential as follows:

| VC 2.x field | Source |
|---|---|
| `@context` | `["https://www.w3.org/ns/credentials/v2", "https://nerion.dev/vocab/v1"]` |
| `type` | `["VerifiableCredential", "NerionPermitCredential"]` |
| `issuer` | PQ DID of the admission authority (did:key over ML-DSA-87 public key, multikey encoding) |
| `credentialSubject.id` | PQ DID of the requesting agent |
| `credentialSubject.action` | `ActionManifest` object |
| `credentialSubject.audience` | `PermitClaims.audience` |
| `credentialSubject.tier` | `PermitClaims.tier` |
| `credentialSubject.effect` | `PermitClaims.effect` |
| `validFrom` | ISO-8601 of token issuance (derived from `PermitClaims.exp` minus TTL, or current time if issuedAt unavailable) |
| `expirationDate` | ISO-8601 of `PermitClaims.exp` |
| `proof` | OMITTED in Phase-A — see note below |

**Proof field**: The VC proof would require re-signing the VC envelope under the
authority DID's ML-DSA-87 key. This is Phase-B scope. Phase-A emits the VC
_without_ a `proof` field, which is a valid unsigned VC presentation. Relying
parties MUST treat it as unsigned and verify the underlying `PermitToken` MAC
independently. The module adds a `_nerionPermitMac` extension field carrying
the hex-encoded `PermitToken.mac` and `PermitToken.suite` so the VC can be
re-grounded against the original MAC at any time.

### eIDAS-2.0 / EUDI-VC rendering

The EUDI rendering uses the same `credentialSubject` as the W3C-VC projection
but wraps it in a CBOR-encoded SD-JWT-VC compatible envelope. Phase-A emits a
JSON placeholder with a `_eidas20_note` field explaining this is a
planning-level rendering pending the final EUDI credential schema (ARF v1.4+).
No legal "qualified" claim is made.

### IETF agent-auth-token rendering

Maps to a JWT-style structure aligned with `draft-klrc-aiagent-auth` and OAuth
transaction tokens for agents. Fields:

| JWT claim | Source |
|---|---|
| `sub` | agent PQ DID |
| `iss` | authority PQ DID |
| `aud` | `PermitClaims.audience` |
| `exp` | `PermitClaims.exp` |
| `jti` | `PermitClaims.nonce` |
| `nerion:actionHash` | `PermitClaims.actionHash` |
| `nerion:tier` | `PermitClaims.tier` |
| `nerion:effect` | `PermitClaims.effect` |
| `nerion:permitMac` | hex of `PermitToken.mac` |

Phase-A emits this as a plain JSON object (not a signed JWT) for the same
reason as the VC proof: the signing step is Phase-B. Callers must verify the
original MAC.

### PQ DID encoding

`did:key` method using the W3C DID-key spec with multikey encoding for
ML-DSA-87 public keys. The multicodec prefix for ML-DSA-87 is not yet
registered as final; Phase-A uses the draft prefix `0xed01` (same as used by
`did:key` for Ed25519 today) with a `_pq_multicodec_note` warning that this
MUST be updated when IETF/W3C register the final ML-DSA-87 multicodec prefix.
This is a planning-level placeholder — no production system should rely on it
before the prefix is finalized.

## Phase-A invariants (enforced by module design)

1. `vcProjection.ts` imports ONLY from `../../crypto/src/index.js` (for types
   and hex utilities) and `../../planes/src/permit.js` (for `PermitClaims`
   type). It does NOT call any signing, verification, or key-derivation function.
2. All output is a plain TypeScript object serializable to JSON. No Uint8Array,
   no CBOR encoding in the projection path.
3. The module exports are pure functions: `(PermitToken, PermitClaims, options)
   => ProjectedCredential`. No side effects, no I/O.
4. CI gate: `npm run test` covers round-trip identity (project then read back
   all PermitClaims fields unchanged).

## Phase-A / Phase-B boundary

Phase-B (gated behind `allowUnauditedZk`) adds:
- VC `proof` field: ML-DSA-87 signature over the canonical VC envelope.
- ZK delegation-chain attenuation proof (Groth16 or PLONK over PQ-safe
  commitment scheme — pending audit).

Phase-B is NOT enabled by default, NOT in this ADR, and MUST NOT be merged
without external audit sign-off.

## Consequences

- **+** Nerion PermitTokens are now projectable to W3C-VC / eIDAS-2.0 /
  IETF agent-auth representations, enabling consumption by EU digital identity
  infrastructure and emerging agent-auth IETF standards.
- **+** The projection is purely additive: zero protocol behavior change, zero
  wire-format change, zero KAT impact.
- **-** The W3C-VC and IETF JWT renderings in Phase-A are unsigned (no VC
  proof / no JWT sig). Downstream systems MUST verify the underlying
  PermitToken MAC; the projection alone provides no additional security.
- **-** The ML-DSA-87 multicodec prefix for `did:key` is not yet finalized;
  Phase-A uses a draft value that requires a future update.

## References

- ADR-0025 (standards-binding profile design)
- ADR-0013 (v:2 receipt commitment equality)
- ADR-0015 (per-audience permit keys)
- W3C Verifiable Credentials Data Model 2.0
- W3C DID Core 1.0 / DID-key method
- eIDAS 2.0 Architecture Reference Framework (ARF v1.4)
- IETF draft-klrc-aiagent-auth
- IETF OAuth transaction tokens for agents
- NIST FIPS 204 (ML-DSA)
