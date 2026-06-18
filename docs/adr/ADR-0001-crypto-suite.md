# ADR-0001: Cryptographic suite & SuiteID baseline

- **Status:** Accepted
- **Date:** 2026-06-17
- **Deciders:** PolarSeek architecture
- **Standards verified:** June 2026 against primary sources (NIST CSRC, NSA CNSA 2.0)

## Context

Guardrails: post-quantum by construction; mandatory crypto-agility (negotiable
`SuiteID`, a second non-lattice KEM selectable); target CNSA 2.0 Cat-5 for the
regulated tier; never roll our own primitive. The build spec says "verify
against current FIPS before coding," so the facts below were re-checked at build
time against primary sources rather than trusted from memory.

## Verified standards facts (primary sources, June 2026)

| Standard | Status | Notes |
|---|---|---|
| **FIPS 203** ML-KEM | **FINAL** (2024-08-13) | NIST posted a 2025-11-17 planning note that a future revision will correct an issue; standard remains in force. |
| **FIPS 204** ML-DSA | **FINAL** (2024-08-13) | General-purpose PQ signatures. |
| **FIPS 205** SLH-DSA | **FINAL** (2024-08-13) | Stateless hash-based; conservative roots. |
| **FIPS 206** FN-DSA (Falcon) | **NOT FINAL** (draft/forthcoming) | Reported at the 6th PQC Conf (Sept 2025); IPD pending. **Treat as NOT load-bearing.** |
| **HQC** (code-based KEM) | **SELECTED, not standardized** | Selected 2025-03-11 as the 5th algorithm; → a NIST PQC standard (FIPS **number not yet officially designated**; "FIPS 207" appears only in a NIST CSRC presentation) (draft ~2026, final 2027). **PENDING.** |
| **SP 800-208** LMS/XMSS | **FINAL** (2020-10-30) | Stateful hash-based; firmware/long-term roots. |
| **SP 800-227** KEM recommendations | **FINAL** (2025-09-18) | Secure-use guidance underpinning ML-KEM. |
| **SP 800-230** extra SLH-DSA params | **IPD** (2026-04-13) | Fast-verify/compact params; comment period to 2026-06-12. |
| **CNSA 2.0** algorithm set | Active guidance | ML-KEM-1024, ML-DSA-87, LMS/XMSS, AES-256, SHA-384/512. |
| **CNSA 2.0** timeline | Active guidance | Software/firmware signing: prefer 2025, exclusive 2030. Browsers/servers & cloud: prefer 2025, exclusive 2033. Networking eq.: prefer 2026, exclusive 2030. OS: prefer 2027, exclusive 2033. (Per-category dates: medium confidence — NSA PDFs 403'd direct fetch; corroborated across advisory/FAQ/reports.) |

Citations: csrc.nist.gov/pubs/fips/{203,204,205}/final; nist.gov HQC selection
(2025-03); csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon and
…/fips-207-hqc-kem; csrc.nist.gov/pubs/sp/800/{208,227}/final;
csrc.nist.gov/News/2026/nist-releases-draft-sp-800-230; NSA CNSA 2.0 advisories
(media.defense.gov 2022-09 & 2025-05; nsa.gov press).

## Decision — the SuiteID baseline

Implemented in `crypto/src/suites.ts`. Every signed/encrypted object carries its
`SuiteID`; primitives are resolved through it (no hard-coded algorithm).

| SuiteID | Status | KEM | Signature | Symmetric |
|---|---|---|---|---|
| **PS-1** (general / CNSA-transition, Cat-3) | active | **X-Wing** (X25519 + ML-KEM-768) | ML-DSA-87 | AES-256-GCM / HMAC-SHA-384 / SHA3-SHAKE256 |
| **PS-5** (regulated, CNSA 2.0 Cat-5) | active | **ML-KEM-1024 + ECDH P-384** | ML-DSA-87 | AES-256-GCM / HMAC-SHA-384 / SHA3-SHAKE256 |
| **PS-5-HQC** | pending | HQC-256 (code-based) | ML-DSA-87 | — |
| **PS-5-FN** | not-load-bearing | ML-KEM-1024+P-384 | FN-DSA-1024 (Falcon) | — |

Long-term roots: **SLH-DSA-SHAKE-256f** (implemented) and **LMS/XMSS** (planned,
ceremony-only). Hot-path PermitToken auth: **HMAC-SHA-384** (symmetric; quantum
impact is Grover-quadratic only, so >128-bit PQ margin — confers integrity, not
non-repudiation; that is the nearline plane's ML-DSA job).

**On the spec's literal "X25519 + ML-KEM-1024":** that pairing mismatches
security levels (X25519 ≈ Cat-1 classical vs ML-KEM-1024 Cat-5). For the
regulated tier we therefore pair ML-KEM-1024 with **P-384**, the CNSA-2.0
classical curve — the more defensible Cat-5 hybrid — and reserve X25519 for the
general tier via the IETF X-Wing construction (X25519 + ML-KEM-768). Both use
**vetted library combiners** (`@noble/post-quantum/hybrid`), never a hand-rolled
one. Rationale captured in [ADR-0002](./ADR-0002-ts-reference-and-kem-pairing.md).

## Consequences

- HQC and Falcon are registered as agility placeholders that **fail loudly**
  (`NotImplementedError` with a CONNECT pointer) until standardized/validated.
- Crypto-agility is structural: negotiation picks the most-preferred *active*
  suite and never selects a pending/non-load-bearing one (tested in
  `crypto/test/suites.test.ts`).
- **Re-verify before launch:** FIPS 206 finalization, the HQC standard's
  publication and official FIPS number, SP 800-230 finalization, and CNSA 2.0
  date revisions must be re-checked and this ADR updated before any GA claim.
- **Council note:** the dates above were re-confirmed against NIST primary
  sources on 2026-06-17/18 after the Gemini council seat (no live web access)
  flagged the 2025–26 items as unverifiable. Primary source wins — see
  [../council/P0-verdicts.md](../council/P0-verdicts.md).
- **Suite security floor:** PS-1's floor is **Cat-3** (set by its X-Wing/
  ML-KEM-768 KEM); its ML-DSA-87 signatures are intentionally over-provisioned
  to Cat-5 so a single signing stack serves both tiers. PS-5 is Cat-5 throughout.
