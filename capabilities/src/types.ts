/**
 * Typed capability model — the true core of authority in PolarSeek.
 *
 * A capability is a typed, PQ-signed grant of authority over ACTIONS. Authority
 * is **attenuation-only** (UCAN / macaroon style): a delegation may narrow a
 * grant along every dimension but can never broaden it. The admission kernel
 * resolves capabilities as a pure function; capabilities carry no perception
 * concepts and no cross-decision state. Aggregate caps are checked against an
 * explicit, externally-supplied **signed scalar** — never an in-kernel counter.
 */

import type { Bytes } from '../../crypto/src/index.js'

export type RiskTier = 0 | 1 | 2 | 3

/** A single typed action the agent proposes (the verb). Never perception. */
export interface ActionIntent {
  /** Action type, e.g. 'payment.transfer', 'infra.deploy', 'data.read'. */
  readonly type: string
  /** Opaque resource identifier the action targets. */
  readonly resource: string
  /** Optional opaque counterparty reference (never re-identified across calls). */
  readonly counterparty?: string
  /** Optional integer amount (minor units). Integers only — no float nondeterminism. */
  readonly amount?: number
  /** Optional typed parameters (hashed into receipts, never perception data). */
  readonly params?: Readonly<Record<string, unknown>>
}

/**
 * The typed scope of a grant. `null` on a dimension means "unrestricted on this
 * dimension" (which a child may then restrict, never the reverse).
 */
export interface CapabilityGrant {
  readonly id: string
  /** hex of the issuer/delegator public key. */
  readonly issuer: string
  /** hex of the subject/delegatee (holder) public key. */
  readonly subject: string
  /** Allowed action types (explicit; default-deny means no wildcard authority). */
  readonly actions: readonly string[]
  /** Max integer amount per single action, or null for unrestricted. */
  readonly perActionCeiling: number | null
  /** Rolling aggregate ceiling, enforced via a signed scalar input, or null. */
  readonly aggregateCap: number | null
  /** Allowed counterparties, or null for unrestricted. */
  readonly counterparties: readonly string[] | null
  /** Highest risk tier this grant authorizes. */
  readonly maxTier: RiskTier
  /** Validity window (unix seconds); compared against an explicit `now` input. */
  readonly notBefore: number
  readonly notAfter: number
  /** Whether the holder may delegate (always attenuating) further. */
  readonly delegable: boolean
}

/** One signed link in a capability chain (root or delegation). */
export interface CapabilityLink {
  readonly grant: CapabilityGrant
  readonly suite: string
  readonly signerPublicKey: Bytes
  readonly sig: Bytes
}

/** A capability is a non-empty chain: root grant + attenuating delegations. */
export interface Capability {
  readonly chain: readonly CapabilityLink[]
}

/** Explicit evaluation context — all inputs are passed in; nothing is ambient. */
export interface EvalContext {
  /** Unix seconds, supplied explicitly (the kernel never reads a clock). */
  readonly now: number
  /** Risk tier of the intent, computed by policy (see kernel). */
  readonly tier: RiskTier
  /** Externally-computed, signed aggregate already consumed (the signed scalar). */
  readonly observedAggregate: number
  /** hex of the requesting holder's public key (must equal the chain's tail subject). */
  readonly holder?: string
}
