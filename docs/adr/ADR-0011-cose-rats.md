# ADR-0011: COSE_Sign1 + RATS/EAT attestation profile

**Status:** Accepted. A byte-conformant IETF COSE_Sign1 (RFC 9052) signing envelope over PolarSeek's PQ
signatures, plus a RATS/EAT (RFC 9711 / RFC 9334) attestation-result profile. The gov-standards team
ranked this #4 — it closes the single COSE encoding gap that blocked byte-level SCITT and RATS
conformance.

## Context

The gov-standards gap map found PolarSeek's transparency log + attestation are "SCITT-style" and
"RATS-style" but **not byte-conformant**: signing used a bespoke `SignedEnvelope` (canonical CBOR +
raw ML-DSA), not the standard **COSE_Sign1** that SCITT signed-statements and RATS attestation-results
are carried in. COSE_Sign1 was the single shared encoding gap.

## Decision

Add `crypto/src/cose.ts`: a standard **COSE_Sign1** (RFC 9052 §4.2):
`[protected: bstr, unprotected: map, payload: bstr, signature: bstr]`, where the signed bytes are the
**Sig_structure** (§4.4) `["Signature1", protected, external_aad, payload]`, and `alg` is protected-
header label 1.

- `coseSign1` / `coseSign1Verify` — sign/verify over any active suite's PQ signature scheme.
  Verification compares the protected header **byte-exact** to the expected alg (no decode ambiguity)
  and checks the signature over the Sig_structure; fail-closed.
- `encodeCoseSign1` / `decodeCoseSign1` — the CBOR wire form.
- `signEatResult` — a RATS/EAT attestation-result: a nonce-bound CBOR claims map (EAT `nonce` = key 10)
  signed as a COSE_Sign1. The byte-conformant form a RATS Relying Party / SCITT verifier consumes.

Wired as conformance check **C19**: sign/verify, alg-binding, wrong-key/tamper/wrong-aad rejection, and
a RATS/EAT result wire round-trip.

## Consequences — honest accuracy (council-checked)

- **ML-DSA-87 = COSE alg -50** (ML-DSA-44 = -48, ML-DSA-65 = -49). These code points are **IANA
  PROVISIONAL via draft-ietf-cose-dilithium — NOT a final RFC** (Grok corrected an earlier "RFC 9964"
  attribution, which was a fetch hallucination). Cited as provisional; when IANA finalizes, only the
  constant changes.
- All other byte-level facts (COSE_Sign1 tag 18, the Sig_structure field order, alg label 1, EAT
  `nonce` = 10, RATS roles) were council-confirmed correct.
- **Scope:** this is the conformant COSE_Sign1 *structure* + a minimal EAT profile. It is NOT a full
  SCITT transparency-service profile or a complete RATS appraisal pipeline — those compose on top of
  this envelope (the existing `translog` is the SCITT transparency service; `attest` is the RATS
  Attester/Verifier). The wire form here is untagged COSE_Sign1 (tag 18 optional, conveyed by
  content-type) — documented, not silently omitted.
- FTO still required; grounded entirely in public IETF/IANA material. No classified material.

## Credits

Gov-standards team (rank #4). Standards facts council-fact-checked (Grok) before implementation — the
ML-DSA code-point RFC attribution was corrected to IANA-provisional.
