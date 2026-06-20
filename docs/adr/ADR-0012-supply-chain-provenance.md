# ADR-0012: Supply-chain provenance — signed SBOM + SLSA

**Status:** Accepted. A CycloneDX-style SBOM and an in-toto / SLSA Provenance v1 statement, signed as
COSE_Sign1 (ADR-0011) and anchorable in the transparency log. The gov-standards gap map flagged
SBOM/SLSA as the "highest-leverage buildable supply-chain artifact and a frequent procurement gate."

## Context

EO 14028, NIST SSDF (SP 800-218), and SLSA require software producers to emit a **software bill of
materials** and **signed build provenance**. PolarSeek had neither. With the COSE_Sign1 layer now in
place, both are a deterministic projection of the dependency set + the build, signed with the same
PQ machinery as every other PolarSeek artifact.

## Decision

Add `conformance/src/supplychain.ts`:
- `buildSbom(components?, now)` → a CycloneDX-style SBOM (sorted, deterministic) defaulting to
  PolarSeek's real direct dependencies (`@noble/*`, `cbor2`).
- `buildSlsaProvenance({subjectName, subjectSha256, buildType, builderId, ...})` → an in-toto
  `Statement/v1` carrying a `slsa.dev/provenance/v1` predicate (subject digest, build type, resolved
  dependencies, builder id).
- `signSupplyChainStatement` / `verifySupplyChainStatement` / `supplyChainLeaf` — sign as COSE_Sign1
  (ML-DSA-87), verify, and anchor in the transparency log.

Wired as conformance check **C20**: sign + verify an SBOM and a provenance statement, reject a wrong
key, and anchor with a verifiable inclusion proof.

## Consequences — honest scope

- This emits + signs the **standard shapes**. A COMPLETE SBOM enumerates the full *transitive*
  dependency graph from the lockfile; **SLSA L2/L3 requires a hardened, hosted build platform** to
  *produce* the provenance (a non-falsifiable builder identity) — those are CI/ops concerns and are NOT
  claimed here. This is the conformant artifact format + the PQ signing/anchoring layer those pipelines
  feed.
- The default dependency list is the direct deps from `package.json`; a real release pipeline supplies
  the full resolved set + artifact digests.
- Grounded in public guidance; no classified material. FTO unaffected.

## Credits

Gov-standards gap map (SBOM/SLSA = top buildable supply-chain gap). Composes the COSE_Sign1 layer
(ADR-0011) and mirrors the CBOM (ADR-0009) signed-artifact pattern.
