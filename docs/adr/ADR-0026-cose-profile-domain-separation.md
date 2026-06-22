<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0026: COSE application/profile domain separation

**Status:** Accepted (implemented). Closes RECEIPT/COSE-PROFILE-001 (Team Apex round-2 sweep).

## Context

Nerion's COSE_Sign1 layer (`crypto/src/cose.ts`) signs three distinct applications under one suite
key: EAT attestation results (`signEatResult`), CycloneDX SBOMs, and SLSA provenance
(`signSupplyChainStatement`). Each produced the same signed `Sig_structure` shape with an **empty
`external_aad`**, and no verifier inspected the payload type. Because all three use COSE alg -50
(ML-DSA-87), a signature minted for one application **verified as another** under a shared key — e.g.
an EAT result accepted by `verifySupplyChainStatement` and anchored as an SLSA provenance leaf
(confirmed by the council, 2/3). This is a cross-profile evidence-substitution / laundering gap.

## Decision

Bind a **per-application profile domain separator** as the COSE `external_aad` (the hook already
exists in `coseSign1`/`coseSign1Verify`):

- `COSE_PROFILE.EAT_RESULT` = `polarseek/cose/eat-result/v1`
- `COSE_PROFILE.CYCLONEDX_SBOM` = `polarseek/cose/cyclonedx-sbom/v1`
- `COSE_PROFILE.SLSA_PROVENANCE` = `polarseek/cose/slsa-provenance/v1`

`signEatResult` binds the EAT profile; `signSupplyChainStatement` derives the profile from the
statement shape (`bomFormat` → SBOM, in-toto `_type` → provenance) and binds it — **failing closed on
an ambiguous (both-shapes) or unrecognized statement** (council hardening: never sign under a guessed
or fallback profile, so the bound profile is always exactly one registered `COSE_PROFILE`). `verifySupplyChainStatement`
now requires the relying party to declare the **`expectedProfile`** it is verifying, and the EAT
relying party verifies with the EAT profile aad. A signature minted under one profile fails under any
other — closing the substitution in every direction.

## Consequences

- **Cross-profile substitution is rejected** (EAT ⇄ SBOM ⇄ SLSA), verified by new regression tests in
  `crypto/test/cose.test.ts`, `conformance/test/supplychain.test.ts`, and the C19/C20 conformance
  checks (which now also assert no-cross).
- **No frozen-vector regeneration.** Conformance C19/C20 are **live self-consistency** checks (sign
  with a fresh key, verify, confirm tamper fails) — not pinned signature KATs. Adding the profile aad
  changes both the sign and verify sides together, so the checks re-derive and stay green. **SuiteID
  `Ps1` and `conformance/vectors/ps-*.json` are UNCHANGED.**
- **Interop note:** an external COSE / SCITT / RATS verifier must supply the matching `external_aad`
  to verify a Nerion COSE statement. Nerion is pre-launch with no deployed COSE artifacts, so this
  behavior change breaks nothing in the field.
- **Residual (follow-up):** after the signature check, relying parties should also assert the decoded
  payload's own type tag (`predicateType` / `bomFormat` / EAT profile) as defense in depth. Tracked,
  not required for the substitution fix.
