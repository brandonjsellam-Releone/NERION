# ADR-0008: CNSA 2.0 conformance oracle

**Status:** Accepted. A machine-checkable classification of PolarSeek's algorithm suites against
NSA's Commercial National Security Algorithm Suite 2.0 — the verifiable gov-facing evidence a
National Security Systems reviewer wants. First upgrade from the public US-gov standards track.

## Context

PolarSeek already *uses* CNSA 2.0's core algorithms (ML-DSA-87, ML-KEM-1024, AES-256, SHA-384), but
"we use the right algorithms" is an assertion. For US/Israel-gov and BlackRock credibility we want a
**runtime, checkable** statement of exactly which suites meet CNSA 2.0, where they are transitional,
and where the real gaps are — produced by code, not a slide.

The approved CNSA 2.0 set (fact-checked June 2026 via the NSA CSA): **ML-DSA-87** (FIPS 204, Cat-5
only), **ML-KEM-1024** (FIPS 203, Cat-5 only), **AES-256**, **SHA-384/512** for general hashing
(SHA3/SHAKE only for internal hardware integrity), and **LMS / single-tree XMSS** (SP 800-208) — or
ML-DSA-87 — for software/firmware signing. **SLH-DSA/SPHINCS+ (FIPS 205) is explicitly EXCLUDED**, as
are Falcon/FN-DSA, HQC, and ML-KEM-512/768. Milestones: NSS support+prefer 2025; software/firmware
exclusive-use 2030; from **Jan 1 2027** all new NSS acquisitions must support CNSA 2.0.

## Decision

Add `crypto/src/cnsa.ts`: `assessCnsa20(suite) -> CnsaAssessment` classifying each component
(signature / kem / symmetric / mac / hash) as **conformant | transitional | non-conformant** with a
cited note, and rolling up to `conformant` (no non-conformant component) and `pureCnsa` (every
component conformant). Wired as conformance check **C15** (15/15).

Honest results it produces:
- **PS-5** (Cat-5): `conformant: true, pureCnsa: false`. ML-DSA-87 ✓, AES-256 ✓, HMAC-SHA-384 ✓;
  ML-KEM-1024**+P-384** is **transitional** (CNSA 2.0's target is pure ML-KEM-1024); SHA3/SHAKE general
  hashing is a **transitional advisory** (CNSA general hashing is SHA-384/512).
- **PS-1** (transition tier): `conformant: false` — X-Wing uses **ML-KEM-768**, which CNSA 2.0 does not
  approve. The oracle correctly refuses to call it CNSA 2.0.
- A suite carrying **SLH-DSA** or **FN-DSA** is flagged `non-conformant` (excluded from CNSA 2.0),
  even though SLH-DSA is FIPS 205 — a distinction a naive "is it post-quantum?" check would miss.

## Consequences — honest scope

- This asserts **algorithm-suite** conformance only. It is **NOT** FIPS 140-3 module validation (needs
  a CMVP lab), and **NOT** full CNSA 2.0 compliance (key management, protocol profiles, and the
  **LMS/XMSS code-signing** requirement — a genuine gap PolarSeek does not yet implement; tracked as
  the next gov-standards upgrade).
- The transitional classification is deliberate honesty: PolarSeek's hybrid KEM (ML-KEM-1024+P-384) is
  *more* than CNSA requires (adds classical defense-in-depth) but is not CNSA-*pure*; the oracle says
  so rather than overclaiming.
- Grounded in public/declassified NSA guidance only. No classified material.

## Credits

First build of the public US-gov standards track (NSA CNSA 2.0 / NIST FIPS 203/204/205 / SP 800-208).
Next on that track: LMS/XMSS (SP 800-208) stateful hash-based code-signing, and a SCITT/RATS
supply-chain transparency profile over the existing `translog` + `attest`.
