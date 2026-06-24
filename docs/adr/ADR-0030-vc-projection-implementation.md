<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0030: VC-Projection Implementation — B12 Phase-A Standards-Binding Profile

**Status:** Accepted — Phase-A implementation of ADR-0025 (Standards-Binding Profile).
ADDITIVE ONLY. UNAUDITED. Pre-FTO. No legal conformity claim is made.
Phase-B (ZK delegation-chain attenuation, `allowUnauditedZk`) remains design-only and
explicitly out of scope.

Date: 2026-06-24

## Context

ADR-0025 specified a three-layer standards-binding strategy for Nerion's PermitToken:

1. Action Manifest (buildable-now, dCBOR schema)
2. Credential / identity binding (buildable-now, W3C VC + eIDAS-2.0 + IETF agent-auth)
3. ZK delegation-chain attenuation (research-bet, gated behind `allowUnauditedZk`)

This ADR records the Phase-A implementation decisions for the
`planes/src/vc-projection.ts` module, which delivers layer 2. It is the B12 Phase-A
completion record for the innovation sprint standards-binding deliverable.

## Decision

Implement `planes/src/vc-projection.ts` as a pure serialization module that accepts a
**caller-verified** `PermitToken` + its decoded `PermitClaims` + the `ActionIntent` +
the raw ML-DSA-87 public key bytes of the issuer and agent, and returns a
`PermitProjection` containing three descriptors:

| Output type | Standard target | Phase-A status |
|---|---|---|
| `VcProjection` | W3C VC Data Model 2.0 draft | Unsigned — no `proof` field |
| `EidasDescriptor` | EUDI ARF v1.4 SD-JWT VC profile | Unsigned planning-level rendering |
| `AgentAuthDescriptor` | IETF draft-klrc-aiagent-auth / OAuth agent transaction tokens | Unsigned JSON object |

The module also exports `buildDidKey(publicKeyBytes)` which constructs a `did:key` DID
from ML-DSA-87 public key bytes using multicodec prefix `0xed01`. This prefix follows
community convention; it is NOT yet finalized in the IANA multicodec registry as of
June 2026. It MUST be updated when the canonical prefix is registered.

### Standards alignment

**W3C VC 2.0 draft**: `@context` uses `https://www.w3.org/ns/credentials/v2` and the
`validFrom` field (VC 2.0 conventions). `credentialSubject` carries `NerionCredentialSubject`
with all `PermitClaims` and `ActionIntent` fields. `issuer` and `credentialSubject.id` are
`did:key` DIDs. The `proof` field is intentionally absent — the underlying HMAC-SHA-384
MAC is the cryptographic binding; the VC envelope is for ecosystem interoperability only.
The `_nerionPhase: 'A-unsigned'` marker makes this explicit. A `nerionPermitSuite`
extension field carries the suite tag for audit consumers.

**eIDAS-2.0 / EUDI ARF v1.4**: `EidasDescriptor` follows SD-JWT VC field naming
(`vct`, `iss`, `sub`, `aud`, `exp`, `iat`, `claims`). The `vct` URI
`https://nerion.trelyan.com/credentials/permit/v1` is provisional — not a registered type
URI. Not a legal "qualified" eIDAS claim; technically interoperable only.

**IETF agent-auth**: `AgentAuthDescriptor` maps to the JWT claim set from
`draft-klrc-aiagent-auth` and the OAuth transaction-tokens-for-agents draft. Fields `sub`,
`aud`, `exp`, `iat`, `jti` (via `sessionId`) plus Nerion-namespaced extensions
`nerionProtocol`, `actionHash`, `tier`, `effect`. Not a submission-ready claim.

### DID key encoding

```
did:key:u<base64url_nopad(varint(0xed01) || raw_public_key_bytes)>
```

The `u` multibase prefix signals base64url encoding. ML-DSA-87 public keys are 2592 bytes;
base58btc (the `z` prefix used for Ed25519 in the did:key spec) is impractical at this
size. The `u`+base64url encoding follows current PQ key practice and the
`draft-multiformats-multibase` spec.

### Hard invariants (permanently enforced)

1. `vc-projection.ts` imports ONLY types from `../../crypto/src/index.js` and `./permit.js`.
   It calls NO runtime functions from those modules.
2. The module never invokes `issuePermit`, `verifyPermit`, `signEnvelope`,
   `verifyEnvelope`, `deriveAudiencePermitKey`, or any HMAC / HKDF / ML-DSA / SLH-DSA
   operation.
3. `PermitToken.body`, `.mac`, `.suite` are read but never mutated.
4. `SuiteID Ps1` and `conformance/vectors/ps-*.json` are untouched.
5. All exports are pure functions: same inputs → same outputs, no side effects, no I/O.
6. `npm run gate` (cleanroom + format + typecheck + test) must remain green.

### Why the `proof` field is absent in Phase-A

The Nerion PermitToken MAC (HMAC-SHA-384 over the canonical CBOR claims under the
audience-scoped key) is the cryptographic binding (ADR-0015). Adding a VC-native proof
field would require either (a) re-signing the VC envelope with the issuer's ML-DSA-87
key — a new signing call that is not a pure presentation-layer operation — or (b)
copying the MAC bytes into the `proof`, which is semantically incorrect (HMAC is not a
VC DataIntegrityProof). Phase-B can add option (a) after external audit by calling the
existing `signEnvelope` from a higher-level orchestration layer, not from within
`vc-projection.ts`.

## Phase-A / Phase-B boundary

Phase-B adds:
- The VC `proof` field (ML-DSA-87 `DataIntegrityProof` over the canonical VC envelope).
- The ZK delegation-chain attenuation proof (`allowUnauditedZk` gate).

Both are:
- NOT merged without external audit sign-off.
- NOT part of this ADR or its definition of done.

## Definition of Done — B12 Phase-A

- [x] `planes/src/vc-projection.ts` shipped, typechecks cleanly
- [x] `buildDidKey` exported with provisional-prefix documentation
- [x] `VcProjection`, `EidasDescriptor`, `AgentAuthDescriptor` typed and exported
- [x] `projectPermit` pure function exported
- [x] No new crypto calls, no wire-tag changes, no KAT changes
- [x] ADR-0025 status updated from "Proposed" to "Accepted — Phase-A implemented"
- [x] This ADR records implementation decisions and completion

## Consequences

**+** Nerion PermitTokens are now projectable into the W3C-VC, eIDAS-2.0 / EUDI, and
IETF agent-auth ecosystems without any change to the underlying protocol.

**+** Direct NLnet European-Dimension differentiator: eIDAS 2.0 / EU AI Act alignment
is the strongest technical hook available for the NGI Restack application.

**+** Zero protocol behavior change. Zero wire-format change. Zero KAT impact.
Gate must remain green.

**-** Phase-A projections are unsigned VC envelopes. Downstream systems MUST verify the
underlying `PermitToken` MAC independently before trusting projected fields.

**-** ML-DSA-87 `did:key` multicodec prefix `0xed01` is provisional. Requires a future
update when IANA/W3C finalize the prefix.

**-** `vct` URI and context URI are provisional and Nerion-controlled; not yet registered
with W3C or any standards body.

## No legal or certification claim

This profile is technically interoperable with the referenced standards. It does NOT
claim eIDAS "qualified" status, W3C conformance certification, FIPS 140-3 conformance,
or non-infringement of any third-party rights. FTO required before any public
non-infringement claim — see [FTO_TODO.md](../FTO_TODO.md).

## References

- ADR-0025 (Standards-Binding Profile — design)
- ADR-0015 (per-audience permit keys, PERMIT-001)
- ADR-0013 (v:2 receipt commitment)
- ADR-0014 (salted intent commitment, RCPT-001)
- W3C VC Data Model 2.0 https://www.w3.org/TR/vc-data-model-2.0/
- W3C DID Core 1.0 https://www.w3.org/TR/did-core/
- W3C did:key method https://w3c-ccg.github.io/did-method-key/
- EUDI ARF v1.4 https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework
- IETF draft-klrc-aiagent-auth https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/
- IETF draft-aip-agent-identity-protocol https://datatracker.ietf.org/doc/draft-aip-agent-identity-protocol/
- NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium)
