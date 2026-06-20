// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/capabilities — typed, attenuable, PQ-signed authority over actions.
 */

export type {
  RiskTier,
  ActionIntent,
  CapabilityGrant,
  CapabilityLink,
  Capability,
  EvalContext,
} from './types.js'
export { authorizesIntent, isAttenuationOf, narrow } from './grant.js'
export type { Attenuation } from './grant.js'
export {
  issueRoot,
  attenuate,
  verifyChain,
  effectiveGrant,
  AttenuationError,
} from './capability.js'
export type { RootGrantSpec } from './capability.js'
export { resolve } from './resolver.js'
export type { ResolveResult } from './resolver.js'
