<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0039: VC-Projection Implementation (Phase-A Standards-Binding)

**Status:** Accepted — Phase-A implementation of ADR-0025 (Standards-Binding Profile).
NOTE: Superseded earlier copy of the VC-projection implementation; the kept VC-projection record is
ADR-0036-vc-projection-implementation.md. Renumbered 0030 -> 0032 -> 0039 across cross-branch ADR
reconciliations. Superseded by the more detailed ADR-0035-standards-binding-profile-phase-a.md and
ADR-0037-b12-standards-binding-phase-a.md for all design decisions; recommend deletion at merge.

## Context

ADR-0025 (Standards-Binding Profile) specified a three-layer standards-binding strategy.
Phase-A (layers 1 and 2) is additive only — a pure presentation layer that maps existing
Nerion PermitTokens and ActionIntents to external credential formats without changing any
signing, verification, or wire-encoding logic.

This ADR records the implementation decision for the `planes/src/vc-projection.ts` module.

## Decision

Implement `vc-projection.ts` as a pure serialization module that accepts a verified
PermitToken + its decoded PermitClaims + the ActionIntent and produces three projection
descriptors:

1. **W3C VC Data Model 1.1 JSON-LD envelope** (`VcProjection`) — the PermitToken claims
   are placed in `credentialSubject` alongside the ActionIntent fields. The `issuer` is
   expressed as a `did:key` DID constructed from the admission authority's ML-DSA-87
   public key with the correct multicodec prefix (0xed01 for ML-DSA-87, per the multicodec
   table / did:key spec). The `@context` includes the W3C VC 1.1 base context; callers may
   extend with domain-specific contexts.

2. **eIDAS-2.0 / EUDI-VC descriptor** (`EidasDescriptor`) — a structured object that
   mirrors the key VC fields in a form compatible with the EUDI Wallet Architecture and
   Reference Framework (ARF v1.4+), including `vct` (Verifiable Credential Type) and
   `claims` extracted from the ActionIntent.

3. **IETF agent-auth-token descriptor** (`AgentAuthDescriptor`) — a structured object
   aligned with the emerging IETF agent-authorization work (draft-klrc-aiagent-auth and
   OAuth transaction tokens for AI agents), carrying `sub` (the agent DID), `aud`
   (the permit audience), `action` (the ActionIntent type), and `exp`.

### Non-changes (hard constraints)

- `vc-projection.ts` NEVER calls `issuePermit`, `verifyPermit`, `signEnvelope`, or any
  function from `crypto/src/`.
- `vc-projection.ts` NEVER mutates `PermitToken.body`, `.mac`, or `.suite`.
- Wire-frozen v:1 SuiteID `Ps1` and `conformance/vectors/ps-*.json` are UNTOUCHED.
- KAT vectors are UNTOUCHED.
- `npm run gate` and `npm run conformance` remain green.

## Standards alignment notes

- **W3C VC**: the implementation uses `https://www.w3.org/ns/credentials/v2` as the
  JSON-LD context URL and the `validFrom` field name, which are VC Data Model 2.0 draft
  conventions (not VC 1.1 — VC 1.1 uses `https://www.w3.org/2018/credentials/v1` and
  `issuanceDate`). The `_nerionPhase: 'A-unsigned'` marker on the output makes explicit
  that no VC-native proof field is present. When VC 2.0 reaches W3C Recommendation, this
  implementation will be conformant without changes; until then it targets the working draft
  and must be treated as provisional. The `proof` field is intentionally absent in Phase-A
  (the Nerion PermitToken MAC is the cryptographic binding; a future Phase-B may add a
  `DataIntegrityProof` with ML-DSA-87 after external audit).
- **did:key**: ML-DSA-87 key type is encoded with multicodec prefix 0xed01, prepended to
  the raw key bytes, then base64url-encoded (no padding) with the 'u' multibase prefix per
  draft-multiformats-multibase. ML-DSA-87 is not yet in the canonical IANA multicodec
  registry; 0xed01 follows community convention and must be treated as provisional.
  A comment in the code notes this.
- **eIDAS-2.0**: targets the EUDI ARF v1.4 SD-JWT VC profile. Not a legal conformity claim.
- **IETF agent-auth**: targets the emerging draft-klrc-aiagent-auth / OAuth transaction
  token for agents work. Not a submission-ready claim.

## No legal or certification claim

This profile is technically interoperable with the referenced standards. It does NOT claim
eIDAS "qualified" status, W3C conformance certification, FIPS conformance, or non-infringement
of any third-party rights.

## References

- ADR-0025 (Standards-Binding Profile — design)
- W3C VC Data Model 1.1 https://www.w3.org/TR/vc-data-model/
- W3C DID Core 1.0 / did:key method https://w3c-ccg.github.io/did-method-key/
- EUDI ARF v1.4 https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework
- draft-klrc-aiagent-auth (IETF agent-authorization, working draft)
- ADR-0015 (per-audience permit keys), ADR-0013 (v:2 receipt), ADR-0018 (amount domain)
