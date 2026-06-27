// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * GOV-POLICY-ALGEBRA — a static analyzer that certifies three properties of a verb-only
 * admission policy, none of which a generic policy engine (Cedar / OPA / UCAN) guarantees
 * for the verb-governance fragment:
 *
 *   - TOTALITY        — every action type maps to exactly one (effect, tier); there are no
 *                       gaps (`defaultTier` covers the complement) and every outcome is a
 *                       valid RiskTier. tierOf is a total function.
 *   - ORDER-INDEPENDENCE — no two tier rules have overlapping namespaces with DIFFERING tiers.
 *                       When this holds, `tierOf` is invariant under any permutation of the
 *                       rule list, so the rule order is NOT semantically load-bearing.
 *   - CONFLICT-FREEDOM — no rule is shadowed (made unreachable) by an earlier, more-general
 *                       rule with a different tier (the live PS-KERNEL-03 mis-tiering class);
 *                       no duplicate prefixes; no action both denied and transformed (deny
 *                       wins in the kernel, so a clashing transform is dead).
 *
 * This is a PURE, additive analyzer + an optional load-time gate. It does NOT change `tierOf`
 * or any decision behaviour, touches no wire format / KAT, and adds no cross-decision state —
 * it strengthens the verb-only governance surface by making policy soundness checkable.
 */

import type { RiskTier } from '../../capabilities/src/index.js'
import type { Policy } from './types.js'

export type DiagnosticSeverity = 'error' | 'warning'

export type DiagnosticCode =
  | 'shadowed-rule'
  | 'duplicate-prefix'
  | 'redundant-rule'
  | 'deny-transform-conflict'
  | 'invalid-tier'
  | 'malformed-prefix'

export interface PolicyDiagnostic {
  readonly code: DiagnosticCode
  readonly severity: DiagnosticSeverity
  readonly message: string
}

export interface PolicyAnalysis {
  /** tierOf is total: no gaps, every outcome a valid RiskTier. */
  readonly total: boolean
  /** tierOf is invariant under any permutation of the tier rules. */
  readonly orderIndependent: boolean
  /** No blocking diagnostics (no shadowed rule, duplicate prefix, or deny/transform clash). */
  readonly conflictFree: boolean
  readonly diagnostics: readonly PolicyDiagnostic[]
}

const isRiskTier = (t: unknown): t is RiskTier => t === 0 || t === 1 || t === 2 || t === 3

/**
 * Does rule prefix `a` cover the entire namespace-language of prefix `b`? Mirrors `tierOf`'s
 * SEGMENT-wise matching exactly (PS-KERNEL-03): `a` covers `b` iff `b === a` or `b` is a dotted
 * child of `a`. So `data` covers `data.read`, but `data.read` does NOT cover `data.readX`.
 */
function covers(a: string, b: string): boolean {
  if (a === b) return true
  const boundary = a.endsWith('.') ? a : a + '.'
  return b.startsWith(boundary)
}

/**
 * Is a rule prefix malformed — i.e. does it contain an EMPTY namespace segment? A single trailing
 * dot is a VALID namespace marker (`payment.` matches `payment.transfer`, exactly as `tierOf`
 * treats it, and the shipped DEFAULT_POLICY uses this form). Only empty, leading-dot, or
 * consecutive-dot ("..") prefixes are malformed: they denote an empty segment the author almost
 * certainly did not intend, and would make the coverage analysis below misleading.
 */
function malformedPrefix(p: string): boolean {
  return p.length === 0 || p.startsWith('.') || p.includes('..')
}

/**
 * Analyze a policy for totality, order-independence, and conflict-freedom. Pure and total;
 * never throws. Rule indices in messages are positions in `policy.tierRules`.
 */
export function analyzePolicy(policy: Policy): PolicyAnalysis {
  const diagnostics: PolicyDiagnostic[] = []
  const err = (code: DiagnosticCode, message: string): void => {
    diagnostics.push({ code, severity: 'error', message })
  }
  const warn = (code: DiagnosticCode, message: string): void => {
    diagnostics.push({ code, severity: 'warning', message })
  }

  const rules = policy.tierRules
  let orderIndependent = true

  for (let i = 0; i < rules.length; i++) {
    const a = rules[i]!
    if (!isRiskTier(a.tier)) {
      err(
        'invalid-tier',
        `tier rule ${i} ("${a.prefix}") has a non-RiskTier tier ${String(a.tier)}`,
      )
    }
    if (malformedPrefix(a.prefix)) {
      err(
        'malformed-prefix',
        `tier rule ${i} prefix "${a.prefix}" has an empty namespace segment (empty, leading dot, or "..")`,
      )
    }
    for (let j = i + 1; j < rules.length; j++) {
      const b = rules[j]!
      if (a.prefix === b.prefix) {
        err(
          'duplicate-prefix',
          `duplicate tier-rule prefix "${a.prefix}" at positions ${i} and ${j}`,
        )
        if (a.tier !== b.tier) orderIndependent = false
        continue
      }
      const aCoversB = covers(a.prefix, b.prefix)
      const bCoversA = covers(b.prefix, a.prefix)
      if (!aCoversB && !bCoversA) continue // disjoint namespaces — mutually independent

      // Overlapping namespaces with differing tiers ⇒ outcome depends on rule order.
      if (a.tier !== b.tier) orderIndependent = false

      if (aCoversB) {
        // The earlier rule `a` is the more-general one: it already matches everything `b` would,
        // so `b` (later, more specific) is UNREACHABLE.
        if (a.tier !== b.tier) {
          err(
            'shadowed-rule',
            `tier rule ${j} ("${b.prefix}" → tier ${b.tier}) is unreachable: earlier rule ${i} ` +
              `("${a.prefix}" → tier ${a.tier}) already covers its namespace`,
          )
        } else {
          warn(
            'redundant-rule',
            `tier rule ${j} ("${b.prefix}") is redundant: covered by earlier same-tier rule ${i} ("${a.prefix}")`,
          )
        }
      }
      // bCoversA with `a` earlier and more specific is the intended specific-over-general override:
      // reachable in this order (no shadow), but still order-dependent if tiers differ (flagged above).
    }
  }

  const denySet = new Set(policy.denyActions)
  for (const t of policy.transformActions) {
    if (denySet.has(t)) {
      err(
        'deny-transform-conflict',
        `action "${t}" is in both denyActions and transformActions; deny is checked first, so the transform is unreachable`,
      )
    }
  }

  const total = isRiskTier(policy.defaultTier) && rules.every((r) => isRiskTier(r.tier))
  if (!isRiskTier(policy.defaultTier)) {
    err('invalid-tier', `defaultTier ${String(policy.defaultTier)} is not a RiskTier (0..3)`)
  }

  const conflictFree = !diagnostics.some((d) => d.severity === 'error')
  return { total, orderIndependent, conflictFree, diagnostics }
}

/**
 * Optional load-time / CI gate: throw if a policy has any blocking (error) diagnostic, so an
 * ill-formed policy (shadowed rule, duplicate prefix, deny/transform clash, invalid tier) is
 * rejected up front rather than silently mis-tiering at decision time. Additive — the kernel
 * does not call this today; wiring it into policy ingestion is a deliberate follow-up (it would
 * turn a previously-accepted-but-shadowed policy into a fail-closed reject).
 */
export function assertWellFormedPolicy(policy: Policy): void {
  const { diagnostics } = analyzePolicy(policy)
  const errors = diagnostics.filter((d) => d.severity === 'error')
  if (errors.length > 0) {
    throw new Error(`ill-formed policy: ${errors.map((e) => e.message).join('; ')}`)
  }
}
