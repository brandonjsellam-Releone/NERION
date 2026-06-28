// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Pure predicates over grants: does a grant authorize an intent, and is one
 * grant a valid attenuation (narrowing) of another. These are the heart of the
 * formally-relevant property "attenuation never amplifies authority".
 */

import type { ActionIntent, CapabilityGrant, EvalContext, RiskTier } from './types.js'

/** Does `grant` authorize `intent` under the explicit context? Pure, total. */
export function authorizesIntent(
  grant: CapabilityGrant,
  intent: ActionIntent,
  ctx: EvalContext,
): boolean {
  if (!grant.actions.includes(intent.type)) return false
  // Fail closed on a malformed clock at the trust boundary: `now` is caller-
  // supplied (the kernel reads no clock), and a non-finite value (NaN/±Infinity)
  // makes BOTH window comparisons false, silently skipping the notBefore/notAfter
  // gate so an expired or not-yet-valid grant would authorize. Guard it like
  // tier/amount/aggregate already are (KERNEL-TIME-001, Team Apex 2026-06-21).
  if (!Number.isSafeInteger(ctx.now)) return false
  // The signed GRANT's own window must be finite too: a non-finite notBefore/notAfter (NaN/
  // Infinity) makes BOTH comparisons below false, silently skipping expiry so the grant would
  // authorize FOREVER (CAP-WINDOW-001 — the KERNEL-TIME-001 / GOV-WINDOW-001 class; flagged as the
  // grant.ts follow-up in the GOV-WINDOW-001 fix). Guard the bounds like the clock.
  if (!Number.isSafeInteger(grant.notBefore) || !Number.isSafeInteger(grant.notAfter)) return false
  if (ctx.now < grant.notBefore || ctx.now > grant.notAfter) return false
  // Defense in depth at the trust boundary: an undefined/negative/non-integer tier
  // would make `ctx.tier > maxTier` false and skip the cap (CAP-001, Team Apex).
  if (!(Number.isSafeInteger(ctx.tier) && ctx.tier >= 0)) return false
  // The signed GRANT's own maxTier must be finite too (Team Apex missed-classes sweep 2026-06-28):
  // a non-finite maxTier (NaN/Infinity from a malformed/misconfigured trusted-signed grant) makes
  // `ctx.tier > maxTier` false, silently skipping the tier cap so the grant authorizes ANY tier. A
  // delegated NaN cannot reach here (isAttenuationOf rejects it), but a ROOT signed with a malformed
  // maxTier could — guard it like the window/ctx above. Fail closed.
  if (!(Number.isSafeInteger(grant.maxTier) && grant.maxTier >= 0)) return false
  if (ctx.tier > grant.maxTier) return false

  if (grant.counterparties !== null) {
    if (intent.counterparty === undefined) return false
    if (!grant.counterparties.includes(intent.counterparty)) return false
  }

  // Fail closed on malformed numeric inputs at the trust boundary: a non-finite,
  // non-integer, or negative amount/aggregate would otherwise slip past the
  // ceiling comparisons (NaN/Infinity make `>` false). PS-CAP-01 / PS-CAP-02.
  if (intent.amount !== undefined && !(Number.isSafeInteger(intent.amount) && intent.amount >= 0)) {
    return false
  }
  if (!(Number.isSafeInteger(ctx.observedAggregate) && ctx.observedAggregate >= 0)) return false

  const amount = intent.amount ?? 0
  // The signed GRANT's own ceilings must be finite when set (Team Apex missed-classes sweep): a
  // non-null but non-finite perActionCeiling/aggregateCap makes `amount > NaN` false, skipping the
  // cap so the grant authorizes ANY amount. Fail closed on a malformed ceiling.
  if (
    grant.perActionCeiling !== null &&
    !(Number.isSafeInteger(grant.perActionCeiling) && grant.perActionCeiling >= 0)
  ) {
    return false
  }
  if (
    grant.aggregateCap !== null &&
    !(Number.isSafeInteger(grant.aggregateCap) && grant.aggregateCap >= 0)
  ) {
    return false
  }
  if (grant.perActionCeiling !== null && amount > grant.perActionCeiling) return false
  if (grant.aggregateCap !== null && ctx.observedAggregate + amount > grant.aggregateCap) {
    return false
  }
  return true
}

/** A numeric ceiling `child` narrows `parent` iff parent unrestricted, or child ≤ parent. */
function ceilingNarrows(child: number | null, parent: number | null): boolean {
  if (parent === null) return true
  return child !== null && child <= parent
}

/** A set `child` narrows `parent` iff parent unrestricted, or child ⊆ parent. */
function setNarrows(child: readonly string[] | null, parent: readonly string[] | null): boolean {
  if (parent === null) return true
  if (child === null) return false
  const p = new Set(parent)
  return child.every((x) => p.has(x))
}

/** Every numeric dimension of a grant is well-formed (finite, in range). */
function isWellFormedGrantNumerics(g: CapabilityGrant): boolean {
  return (
    Number.isSafeInteger(g.maxTier) &&
    g.maxTier >= 0 &&
    Number.isSafeInteger(g.notBefore) &&
    Number.isSafeInteger(g.notAfter) &&
    (g.perActionCeiling === null ||
      (Number.isSafeInteger(g.perActionCeiling) && g.perActionCeiling >= 0)) &&
    (g.aggregateCap === null || (Number.isSafeInteger(g.aggregateCap) && g.aggregateCap >= 0))
  )
}

/**
 * True iff `child` is a valid attenuation of `parent`: it narrows (or holds
 * equal) on EVERY dimension and broadens on none, and is bound to the parent's
 * subject as its issuer (the delegation link).
 */
export function isAttenuationOf(child: CapabilityGrant, parent: CapabilityGrant): boolean {
  // Defense in depth (Team Apex missed-classes sweep 2026-06-28): monotonicity must NOT depend on
  // the incidental fact that `NaN <= x` is false. A malformed grant (non-finite tier/window/ceiling
  // on either side) is never a valid attenuation; rejecting it explicitly means a future comparator
  // flip cannot silently re-open authority widening, and narrow()'s Math.min/Math.max NaN-propagation
  // can never yield an "accepted" child.
  if (!isWellFormedGrantNumerics(child) || !isWellFormedGrantNumerics(parent)) return false
  const parentActions = new Set(parent.actions)
  return (
    child.issuer === parent.subject &&
    child.actions.every((a) => parentActions.has(a)) &&
    ceilingNarrows(child.perActionCeiling, parent.perActionCeiling) &&
    ceilingNarrows(child.aggregateCap, parent.aggregateCap) &&
    setNarrows(child.counterparties, parent.counterparties) &&
    child.maxTier <= parent.maxTier &&
    child.notBefore >= parent.notBefore &&
    child.notAfter <= parent.notAfter &&
    (!child.delegable || parent.delegable)
  )
}

/** Restrictions applicable when delegating; each may only narrow. */
export interface Attenuation {
  readonly actions?: readonly string[]
  readonly perActionCeiling?: number
  readonly aggregateCap?: number
  readonly counterparties?: readonly string[]
  readonly maxTier?: RiskTier
  readonly notBefore?: number
  readonly notAfter?: number
  readonly delegable?: boolean
}

const minNullable = (a: number | null, b: number | null): number | null => {
  if (a === null) return b
  if (b === null) return a
  return Math.min(a, b)
}

/**
 * Produce a child grant that is guaranteed ⊑ `parent`: every requested
 * restriction is intersected with the parent so the result can never broaden.
 * `issuer`/`subject` set the delegation binding; `id` identifies the child.
 */
export function narrow(
  parent: CapabilityGrant,
  r: Attenuation,
  binding: { id: string; issuer: string; subject: string },
): CapabilityGrant {
  const parentActions = new Set(parent.actions)
  const actions = (r.actions ?? parent.actions).filter((a) => parentActions.has(a))

  const counterparties =
    r.counterparties === undefined
      ? parent.counterparties
      : parent.counterparties === null
        ? r.counterparties
        : r.counterparties.filter((c) => parent.counterparties!.includes(c))

  return {
    id: binding.id,
    issuer: binding.issuer,
    subject: binding.subject,
    actions,
    perActionCeiling: minNullable(r.perActionCeiling ?? null, parent.perActionCeiling),
    aggregateCap: minNullable(r.aggregateCap ?? null, parent.aggregateCap),
    counterparties,
    maxTier: Math.min(r.maxTier ?? parent.maxTier, parent.maxTier) as RiskTier,
    notBefore: Math.max(r.notBefore ?? parent.notBefore, parent.notBefore),
    notAfter: Math.min(r.notAfter ?? parent.notAfter, parent.notAfter),
    delegable: (r.delegable ?? parent.delegable) && parent.delegable,
  }
}
