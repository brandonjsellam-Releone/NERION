<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0031: Innovation Sprint 1 — Standards-Binding Addendum (B12 Phase-A)

**Status:** Accepted — additive companion to ADR-0025 / ADR-0030. UNAUDITED. Pre-FTO. No
legal conformity claim is made.

**Date:** 2026-06-24

---

## Context

ADR-0025 (Standards-Binding Profile) and ADR-0030 (VC-Projection Implementation) specified
and implemented the additive Phase-A projection layer mapping Nerion PermitTokens to W3C VC,
eIDAS-2.0, and IETF agent-auth-token formats. The June 2026 U.S. executive orders and the EU
AI Act's general-purpose AI provisions create a dual mandate: PQC-secured execution governance
AND AI action transparency. This ADR records the Innovation Sprint 1 review and the creation of
the following strategic documents that complete the Phase-A standards-positioning layer:

- `docs/standards/IETF-DRAFT-OUTLINE.md` — strategic planning outline for a future IETF
  internet-draft on PQ execution governance for AI agent systems.
- `docs/standards/EU-AI-ACT-ALIGNMENT.md` — technical alignment map of Nerion's properties
  to EU AI Act Articles 9, 13, 17, and Annex IV.
- `docs/standards/DID-NERION-METHOD.md` — draft outline for a `did:nerion` DID method spec
  identifying an AI agent's governance authority context.

These documents are additive strategic and planning artifacts. They do not introduce new code,
new crypto, or new wire-format elements.

---

## Decision

### 1. Confirmed wire-freeze invariants (Phase-A)

The following constants remain untouched and MUST NOT be altered by any Phase-A deliverable:

| Constant | Location | Value |
|---|---|---|
| `PERMIT_CONTEXT` | `crypto/src/envelope.ts` | `'PolarSeek-Permit-v1'` |
| `PERMIT_MAC_KEY_BYTES` | `crypto/src/envelope.ts` | `48` |
| `SIGNED_CONTEXT` | `crypto/src/envelope.ts` | `'PolarSeek-Signed-v1'` |
| `AUDIENCE_KDF_CONTEXT` | `crypto/src/envelope.ts` | `'PolarSeek-Permit-AudienceKDF-v1'` |
| SuiteID namespace | `crypto/src/suites.ts` | `PS-1`, `PS-5` (and pending variants) |
| KAT vectors | `conformance/vectors/ps-*.json` | FROZEN |

The `toVerifiableCredential`, `didKeyFromPublicKey`, `manifestDigest`, and `isNamespacedVerb`
functions exported from `capabilities/src/profile.ts` are the ONLY Phase-A additions to
operational code. None of them touch signing, verification, key derivation, or wire encoding.

### 2. Proof-field omission rationale

The W3C VC 2.0 object produced by `toVerifiableCredential` deliberately omits the `proof`
property. This is correct for Phase-A because:

- The Nerion `SignedEnvelope` (ML-DSA-87, `signEnvelope`/`verifyEnvelope`) is the proof
  carrier. External verifiers match the `credentialSubject.manifestDigest` against the digest
  committed into the PQ-signed envelope.
- Attaching a VC `proof` would require re-signing the VC under the authority DID's ML-DSA-87
  key, which is Phase-B scope and requires additional audit review.
- An unsigned VC is a valid W3C VC 2.0 data object (the spec makes `proof` optional).
- Relying parties MUST treat the VC as unsigned and verify the underlying PermitToken MAC and
  the Nerion receipt signature independently.

### 3. ML-DSA-87 multicodec provisional status

The multicodec code for ML-DSA-87 keys in `did:key` is not yet finalized in the upstream
multicodec registry. ADR-0030 records the community-provisional value `0xed01`. Any
`did:key` identifier produced by `didKeyFromPublicKey` with this code MUST be labeled
provisional in documentation and tooling until the canonical registry assignment ships.
This does not affect the Nerion wire protocol.

### 4. eIDAS-2.0 alignment scope

eIDAS-2.0 (Regulation (EU) 2024/1183) mandates W3C VC 2.0 as the credential format for EUDI
wallets. Nerion's `toVerifiableCredential` output is a presentation-layer adapter, not an
eIDAS-qualified credential issuance. It makes the Nerion permit machine-readable in the
standard format; to obtain a "qualified electronic attestation of attributes," the output
would need to be wrapped by a qualified trust service. No such claim is made here.

### 5. `did:nerion` DID method (planning only)

`docs/standards/DID-NERION-METHOD.md` is a draft outline for a future DID method. It is NOT
a submitted DID method spec and has no W3C DID Working Group standing. Its main design
point: the DID identifies an AI agent's governance authority context (not the agent's personal
identity), derived deterministically from the Nerion receipt chain, with no mutable registry
required for read operations.

### 6. IETF internet-draft positioning (planning only)

`docs/standards/IETF-DRAFT-OUTLINE.md` is a strategic planning document for a future IETF
submission. It is NOT submitted and has no IETF status. Target: document the three-plane
PQ execution governance model as an IETF Standards Track contribution after Phase-B
stabilization, targeting Q1 2027 for a version-00 draft.

---

## Consequences

- **Additive purity:** The gate (`npm run gate`, `npm run conformance`) remains green. No
  KAT vectors are regenerated. No production verification path is touched.
- **Standards positioning:** Nerion now has formal planning artifacts for IETF, EU AI Act,
  and DID ecosystem engagement, supporting the NLnet Restack grant application.
- **Provisional risk acknowledged:** ML-DSA-87 multicodec code is provisional; final code
  update is a Phase-B documentation task.

## Non-Goals (Phase-B, research-bet, audit-gated)

- ZK delegation-chain attenuation proofs — flagged research item, requires separate audit.
- Wire-tag changes or new CBOR tags.
- Attaching a `proof` field to the VC output (requires re-signing under the authority DID).
- eIDAS-qualified trust service integration.
- VC 2.0 context publication at `https://nerion.dev/vocab/v1` (Phase-B infra task).

## Standards References

- **W3C VC 2.0:** https://www.w3.org/ns/credentials/v2 (Working Draft, June 2026)
- **eIDAS-2.0 ARF:** Regulation (EU) 2024/1183, Architecture Reference Framework v1.4
- **IETF agent-auth-token:** draft-klrc-aiagent-auth (early stage, informational reference)
- **did:key:** W3C DID Specification Registries, did:key method (deterministic, no registry)
- **FIPS 204:** ML-DSA (Module-Lattice-Based Digital Signature Standard)
- **CNSA 2.0:** NSA Commercial National Security Algorithm Suite 2.0
