/**
 * Admission kernel types.
 *
 * The kernel governs typed ACTIONS only (never perception) and is a PURE
 * FUNCTION of its explicit inputs — it holds no memory across decisions, reads
 * no clock, performs no I/O, and increments no counter. Any aggregate limit
 * arrives as an explicit `observedAggregate` scalar (computed and signed
 * elsewhere). This is the combined technical + non-infringement firewall; see
 * docs/CLEANROOM.md.
 */

import type { ActionIntent, Capability, RiskTier } from '../../capabilities/src/index.js'
import type { Bytes } from '../../crypto/src/index.js'

export type Effect = 'allow' | 'deny' | 'transform'

/** A deterministic tier rule: action types matching `prefix` get `tier`. */
export interface TierRule {
  readonly prefix: string
  readonly tier: RiskTier
}

/**
 * A constrained, deterministic policy. No live lookups, no nondeterministic
 * builtins — just ordered, bounded rules over the explicit intent. (A future
 * Rego/Cedar constrained profile conforms to this same shape.)
 */
export interface Policy {
  readonly version: string
  /** First matching prefix wins; unmatched actions get `defaultTier`. */
  readonly tierRules: readonly TierRule[]
  /** Action types that are always denied regardless of capability. */
  readonly denyActions: readonly string[]
  /** Action types that are admitted only in transformed form (e.g. redacted). */
  readonly transformActions: readonly string[]
  /** Tier for actions not matched by any tier rule (conservative default). */
  readonly defaultTier: RiskTier
}

/** Everything the kernel needs — all explicit, nothing ambient. */
export interface KernelInput {
  readonly intent: ActionIntent
  readonly capabilities: readonly Capability[]
  readonly policy: Policy
  readonly trustedRoots: readonly Bytes[]
  /** Unix seconds, supplied by the caller (the kernel never reads a clock). */
  readonly now: number
  /** Signed aggregate already consumed toward any rolling cap (the signed scalar). */
  readonly observedAggregate: number
  /** hex of the requesting holder's public key. */
  readonly holder?: string
}

export interface Decision {
  readonly effect: Effect
  readonly tier: RiskTier
  readonly reasons: readonly string[]
  /** Required follow-on controls (e.g. nearline receipt, dual control). */
  readonly obligations: readonly string[]
  /** Pinned evaluator identity, hashed into receipts for replay. */
  readonly evaluatorVersion: string
}
