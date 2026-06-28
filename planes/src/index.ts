// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/planes — three-plane orchestration + PermitToken binding.
 */

export { PolarSeekNode } from './node.js'
export type { Session, NodeConfig, AdmissionRequest, AdmissionOutcome } from './node.js'
export { actionHash, issueBoundPermit, verifyPermitForAction } from './permit.js'
export type { PermitClaims, PermitCheck, PermitVerdict } from './permit.js'
// Offline, holder-side least-privilege attenuation of a permit (macaroon-style first-party
// caveats; Team Apex R&D 2026-06-28). See docs/PERMIT-CAVEATS.md.
export { attenuate, verifyAttenuatedPermit } from './caveat.js'
export type { Caveat, AttenuatedPermit } from './caveat.js'
// Per-audience permit-key derivation (ADR-0015): resources are provisioned with
// `deriveAudiencePermitKey(sessionKey, theirAudience)`, never the raw session secret.
export { deriveAudiencePermitKey } from '../../crypto/src/index.js'
