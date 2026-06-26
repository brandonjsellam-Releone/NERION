<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0019: Standards-Binding Profile — Phase A (W3C-VC / eIDAS-2.0 projection)

- **Status:** Accepted (Phase A)
- **Date:** 2026-06-24
- **Numbering note:** this ADR was authored on `apex/innovation-sprint1` in parallel
  with other apex branches; the final ADR number is subject to cross-branch
  reconciliation at merge (see the ADR-renumbering cleanup task).

## Context

Nerion's native `PermitToken` and `Receipt` carry rich, post-quantum-signed
semantics (ML-DSA-87 signatures, audience-bound HKDF permit keys, Merkle-anchored
receipts). External ecosystems — SSI wallets, W3C Verifiable-Credentials
verifiers, eIDAS-2.0 attestation consumers — cannot read those native shapes. A
binding profile lets those consumers *see* a Nerion authorization in their own
vocabulary, **without changing Nerion's cryptography**.

The NLnet NGI Restack call explicitly values eIDAS-2.0 alignment; a W3C-VC /
eIDAS projection is the single strongest European-dimension differentiator for
that application, and is buildable now with no new crypto.

## Decision

Add a **purely presentational** projection layer that maps Nerion permit/receipt
data into:

- **W3C Verifiable Credential 2.0** — `NerionPermitCredential` (from a permit),
- **W3C Verifiable Presentation 2.0** — `NerionActionReceiptPresentation`,
- a simplified **eIDAS-2.0 electronic-attestation** shape.

Constraints that make this safe and additive:

1. **No new cryptography.** The module performs no signing or verification and
   imports no crypto function. The VC `proof` block only *references* the native
   ML-DSA-87 signature (`type: NerionMLDSA87Signature2026`); the canonical proof
   remains the native PermitToken / Receipt signature.
2. **Zero coupling / no clock.** The module defines its own minimal *structural*
   input types (`PermitView`, `IntentView`, `ReceiptView`) mirroring
   `PermitClaims` (`planes/`) and `ActionIntent` (`capabilities/`), so it is a
   dependency-free leaf. Timestamps are passed in by the caller — the projection
   is deterministic and side-effect-free.
3. **Placement: the SDK layer, not the crypto cleanroom.** The file lives at
   `sdks/ts/src/vc-projection.ts`, not `crypto/src/`. Rationale: `crypto/src/` is
   the cleanroom primitive layer (and the lowest layer); a presentation
   projection there would risk the `lint:cleanroom` rule and create an
   upward/circular import. W3C-VC projection is a *client* concern, so the SDK
   (top/presentation) layer is its correct home. Exported from
   `sdks/ts/src/index.ts`.

## Phase-A scope (this ADR — buildable now)

- Permit → W3C-VC credential; Receipt → W3C-VP; permit → eIDAS attestation shape.
- Tests: `sdks/ts/test/vc-projection.test.ts`.

## Phase-B scope (deferred, research-track)

- ZK delegation-chain attenuation projected into VC terms (`allowUnauditedZk` gate).
- `did:nerion` verifiable-identifier binding (see `docs/standards/DID-NERION-METHOD.md`).
- eIDAS-2.0 **qualified**-signature alignment — requires an accredited module
  (FIPS 140-3 / CMVP), which Nerion has not initiated.

## Consequences

- **Positive:** standards interoperability with the SSI/eIDAS ecosystem; a
  concrete European-dimension artifact for the NLnet application; zero risk to the
  signing/verification paths (additive, no KAT change, no wire-format change).
- **Honest limits:** the projected documents are *views*, not independently
  verifiable W3C-VCs until a published JSON-LD context and a registered Nerion
  cryptosuite exist (placeholder context URL today). The eIDAS shape is Phase-A
  only and confers no qualified-signature status. Nerion remains UNAUDITED and
  not FIPS-140-3 validated.

## References

- `sdks/ts/src/vc-projection.ts`, `sdks/ts/test/vc-projection.test.ts`
- `docs/standards/EU-AI-ACT-ALIGNMENT.md`, `docs/standards/DID-NERION-METHOD.md`,
  `docs/standards/IETF-DRAFT-OUTLINE.md`
- W3C Verifiable Credentials Data Model 2.0; eIDAS 2.0 (Regulation (EU) 2024/1183)
