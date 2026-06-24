<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0031: B12 Phase-A Standards-Binding Profile — Completion Record

**Status:** Accepted — Phase-A shipped. Additive presentation layer only.
UNAUDITED. Pre-FTO. No legal conformity claim is made. Phase-B (ZK delegation-chain
attenuation, `allowUnauditedZk`) remains design-only and explicitly out of scope.

Date: 2026-06-24

## Context

ADR-0025 (Standards-Binding Profile) and ADR-0030 (VC-Projection Implementation)
specified Phase-A as a pure presentation-layer adapter that projects Nerion
`PermitToken` + `PermitClaims` + `ActionIntent` into three external credential
formats without touching any wire-frozen protocol element.

This ADR records the definitive B12 Phase-A completion: what was built, what
was verified, and what the hard invariants are going forward.

## What was built (Phase-A)

### planes/src/vc-projection.ts

A pure serialization module. It accepts a **caller-verified** `PermitToken`, its
decoded `PermitClaims`, the `ActionIntent`, and the raw ML-DSA-87 public key bytes
of the issuer and agent, and returns a `PermitProjection` containing three
descriptors:

| Output | Standard | Status |
|---|---|---|
| `VcProjection` | W3C VC Data Model 1.1 / VC 2.0 draft | Unsigned (Phase-B adds proof) |
| `EidasDescriptor` | EUDI ARF v1.4 SD-JWT VC profile | Unsigned planning-level rendering |
| `AgentAuthDescriptor` | IETF draft-klrc-aiagent-auth / OAuth agent transaction tokens | Unsigned JSON object |

The module also exports `buildDidKey(publicKeyBytes)` which constructs a
`did:key` DID from ML-DSA-87 public key bytes using the provisional multicodec
prefix `0xed01`. This prefix is NOT yet finalized in IANA/W3C multicodec; it
MUST be updated when the canonical prefix is registered.

### Standards alignment (Phase-A)

- **W3C VC 1.1 / VC 2.0**: `@context` includes the W3C VC base context URI.
  `credentialSubject` carries `NerionCredentialSubject` with all `PermitClaims`
  and `ActionIntent` fields. `issuer` and `credentialSubject.id` are `did:key` DIDs.
  The `proof` field is intentionally absent — the underlying HMAC-SHA-384 MAC is
  the cryptographic binding; the VC envelope is for ecosystem interoperability only.
  A `nerionPermitSuite` extension field carries the suite tag for audit.

- **eIDAS-2.0 / EUDI ARF v1.4**: `EidasDescriptor` follows the SD-JWT VC field
  naming (`vct`, `iss`, `sub`, `aud`, `exp`, `iat`, `claims`). The `vct` URI is
  provisional (`https://nerion.trelyan.com/credentials/permit/v1`). Not a legal
  "qualified" claim.

- **IETF agent-auth**: `AgentAuthDescriptor` maps to the JWT claim set from
  `draft-klrc-aiagent-auth` and the OAuth transaction-tokens-for-agents draft.
  Fields `sub`, `aud`, `exp`, `iat`, `jti` (via `sessionId`) plus Nerion-namespaced
  extensions `nerion:actionHash`, `nerion:tier`, `nerion:effect`. Not a
  submission-ready claim.

## Hard invariants (permanently enforced)

1. `vc-projection.ts` imports type-only from `../../crypto/src/index.js` and
   `./permit.js`. It calls NO function from those modules at runtime.
2. The module never invokes `issuePermit`, `verifyPermit`, `signEnvelope`,
   `verifyEnvelope`, `deriveAudiencePermitKey`, or any HMAC/HKDF/ML-DSA/SLH-DSA
   operation.
3. `PermitToken.body`, `.mac`, `.suite` are read but never mutated.
4. `SuiteID Ps1` and `conformance/vectors/ps-*.json` are untouched.
5. All exports are pure functions: same inputs → same outputs, no side effects.
6. `npm run gate` (cleanroom + format + typecheck + test) remains green.

## Phase-A / Phase-B boundary

Phase-B adds the VC `proof` field (ML-DSA-87 signature over the canonical VC
envelope) and the ZK delegation-chain attenuation proof. Both are:
- Behind `allowUnauditedZk` flag.
- NOT merged without external audit sign-off.
- NOT part of this ADR or its DoD.

## Definition of Done — B12 Phase-A

- [x] `planes/src/vc-projection.ts` shipped and passing typecheck
- [x] `buildDidKey` exported with provisional-prefix documentation
- [x] `VcProjection`, `EidasDescriptor`, `AgentAuthDescriptor` typed and exported
- [x] `projectPermit` pure function exported
- [x] No new crypto calls, no wire-tag changes, no KAT changes
- [x] Gate green (cleanroom lint, format, typecheck, test)
- [x] ADR-0025 and ADR-0030 referenced; this ADR records completion

## Consequences

- **+** Nerion PermitTokens are now projectable into the W3C-VC, eIDAS-2.0 /
  EUDI, and IETF agent-auth ecosystems. This is the strongest NLnet European-
  Dimension differentiator: a direct eIDAS 2.0 / EU AI Act hook with zero
  protocol risk.
- **+** Zero protocol behavior change. Zero wire-format change. Zero KAT impact.
- **-** Phase-A projections are unsigned envelopes. Downstream systems MUST
  verify the underlying `PermitToken` MAC independently.
- **-** ML-DSA-87 `did:key` multicodec prefix is provisional; requires future
  update when IANA/W3C finalize the prefix.

## References

- ADR-0025 (Standards-Binding Profile — design)
- ADR-0030 (VC-Projection Implementation — implementation decisions)
- W3C Verifiable Credentials Data Model 2.0 https://www.w3.org/TR/vc-data-model-2.0/
- W3C DID Core 1.0 https://www.w3.org/TR/did-core/
- W3C did:key method https://w3c-ccg.github.io/did-method-key/
- eIDAS 2.0 / EUDI ARF v1.4 https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework
- IETF draft-klrc-aiagent-auth https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/
- IETF draft-aip-agent-identity-protocol https://datatracker.ietf.org/doc/draft-aip-agent-identity-protocol/
- NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium)
- ADR-0015 (per-audience permit keys), ADR-0013 (v:2 receipt commitment)
