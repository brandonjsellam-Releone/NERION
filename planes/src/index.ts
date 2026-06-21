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
// Per-audience permit-key derivation (ADR-0015): resources are provisioned with
// `deriveAudiencePermitKey(sessionKey, theirAudience)`, never the raw session secret.
export { deriveAudiencePermitKey } from '../../crypto/src/index.js'
