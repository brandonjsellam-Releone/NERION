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
  if (ctx.now < grant.notBefore || ctx.now > grant.notAfter) return false
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

/**
 * True iff `child` is a valid attenuation of `parent`: it narrows (or holds
 * equal) on EVERY dimension and broadens on none, and is bound to the parent's
 * subject as its issuer (the delegation link).
 */
export function isAttenuationOf(child: CapabilityGrant, parent: CapabilityGrant): boolean {
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
