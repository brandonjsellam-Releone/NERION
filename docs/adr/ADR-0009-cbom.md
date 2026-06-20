# ADR-0009: Cryptographic Bill of Materials (CBOM)

**Status:** Accepted. A signed, transparency-anchored machine-readable cryptographic inventory emitted
from the SuiteID registry. The gov-standards team ranked this #2 (after the CNSA oracle). Supports the
NSM-10 / OMB M-23-02 cryptographic-inventory requirement and the NIST PQC-migration framing.

## Context

NSM-10 (May 2022) and OMB M-23-02 require federal agencies to **inventory** systems relying on
quantum-vulnerable cryptography, to prioritize PQC migration. A **Cryptographic Bill of Materials
(CBOM)** is the machine-readable form of that inventory (OWASP CycloneDX 1.6 added a
`cryptographic-asset` component type for exactly this). PolarSeek's SuiteID registry already holds the
data — so the CBOM is a deterministic projection of it, signed and anchored like every other PolarSeek
artifact.

## Decision

Add `conformance/src/cbom.ts`: `buildCbom(now) -> Cbom` enumerates the **active** suites, **decomposes
hybrid KEMs into their legs** (e.g. ML-KEM-1024 + P-384; X-Wing → ML-KEM-768 + X25519), and classifies
each algorithm by primitive, NIST standard, **quantum-resistance class**, and deprecation note, plus a
per-suite CNSA 2.0 level (via `assertCnsa`). `signCbom` / `verifyCbom` / `cbomLeaf` make it an
ML-DSA-87-signed, transparency-log-anchored, externally-verifiable artifact (reusing the signed-
envelope machinery). Wired as conformance check **C17** (17/17).

The headline a migration reviewer wants — `cbom.quantumVulnerable`:
- **Flagged quantum-vulnerable (Shor-broken):** `P-384`, `X25519` (the classical hybrid legs). These
  are the assets a PQC-migration inventory must surface.
- **Not flagged:** `ML-KEM-1024/768`, `ML-DSA-87` (post-quantum lattice), and `AES-256` / `SHA-384` /
  `SHA3-256` (256/384-bit symmetric+hash are only weakened by Grover, remaining quantum-resistant).

## Consequences — honest scope (council-corrected accuracy)

- **NSM-10 / OMB M-23-02 mandate the inventory, NOT a specific format.** A CBOM is a tool that *helps
  satisfy* the inventory requirement; it is not an officially-mandated or certified format. (Grok
  flagged the earlier "valid form of that inventory" as an overstatement — corrected.)
- **The 2030-deprecate / 2035-disallow dates trace to NSA CNSA 2.0 and the NIST PQC transition
  (IR 8547 ipd)** — not to a single NIST IR alone. The CBOM notes attribute them accordingly. (Grok
  flagged the earlier "IR 8547: deprecate after 2030" sole attribution as wrong — corrected.)
- **Scope:** algorithm inventory only — NOT FIPS 140-3 module validation, NOT a full system SBOM, NOT
  a compliance certification. It is verifiable evidence of *what cryptography PolarSeek selects*.
- Deterministic (no ambient clock; sorted) so two honest issuers emit identical CBOMs.
- Grounded entirely in public/declassified guidance. No classified material.

## Credits

Gov-standards team workflow (rank #2). Accuracy fact-checked by the council — Grok corrected the
NSM-10 format-mandate overstatement and the IR 8547 date attribution (Gemini's crypto-verify seat was
unavailable). Next on the gov track: a RATS/COSE attestation-result + EAT-in-COSE profile, which also
closes the COSE_Sign1 encoding gap blocking byte-level SCITT conformance.
