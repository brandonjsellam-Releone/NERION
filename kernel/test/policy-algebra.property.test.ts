// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * GOV-POLICY-ALGEBRA — tests for the policy analyzer: totality, order-independence, and
 * conflict-freedom of the verb-only tier policy. The headline property: a policy the analyzer
 * certifies `orderIndependent` is genuinely invariant under ANY permutation of its rules
 * (fast-check, fixed seed), and a policy it flags as order-dependent has a permutation that
 * changes a decision. Plus shadowed-rule / duplicate / deny∩transform detection and a
 * fault-injection count.
 */

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { tierOf, DEFAULT_POLICY, analyzePolicy, assertWellFormedPolicy } from '../src/index.js'
import type { Policy, TierRule } from '../src/index.js'
import type { ActionIntent, RiskTier } from '../../capabilities/src/index.js'

const FC = { seed: 0x676f7061, numRuns: 200 } as const

const makePolicy = (tierRules: readonly TierRule[], over: Partial<Policy> = {}): Policy => ({
  ...DEFAULT_POLICY,
  tierRules,
  ...over,
})

const intentOf = (type: string): ActionIntent => ({ type, resource: 'r' })

/** All permutations of an array (n! — used only for tiny n in the exhaustive test). */
function permutations<T>(arr: readonly T[]): T[][] {
  if (arr.length <= 1) return [[...arr]]
  const out: T[][] = []
  arr.forEach((x, i) => {
    const rest = [...arr.slice(0, i), ...arr.slice(i + 1)]
    for (const p of permutations(rest)) out.push([x, ...p])
  })
  return out
}

// Action types that exercise real prefixes, namespace children, near-prefixes, and junk.
const arbType = fc.oneof(
  fc.constantFrom(
    'data.read',
    'data.create',
    'data.delete',
    'data.readX', // PS-KERNEL-03 near-prefix: must NOT inherit data.read's tier
    'payment.transfer',
    'key.rotate',
    'infra.deploy',
    'actuation.physical.arm',
    'export.mass.dump',
    'model.weights.read',
    'draft.note',
    'message.send',
    'totally.unknown',
  ),
  fc.string(),
)

describe('GOV-POLICY-ALGEBRA — analyzer certifies the shipped default policy clean', () => {
  it('DEFAULT_POLICY is total, order-independent, conflict-free, no error diagnostics', () => {
    const a = analyzePolicy(DEFAULT_POLICY)
    expect(a.total).toBe(true)
    expect(a.orderIndependent).toBe(true)
    expect(a.conflictFree).toBe(true)
    expect(a.diagnostics.filter((d) => d.severity === 'error')).toEqual([])
    expect(() => assertWellFormedPolicy(DEFAULT_POLICY)).not.toThrow()
  })
})

describe('GOV-POLICY-ALGEBRA — totality (tierOf is a total function)', () => {
  it('returns a valid RiskTier for ANY action type', () => {
    const valid: ReadonlySet<RiskTier> = new Set<RiskTier>([0, 1, 2, 3])
    fc.assert(
      fc.property(arbType, (t) => {
        expect(valid.has(tierOf(intentOf(t), DEFAULT_POLICY))).toBe(true)
      }),
      FC,
    )
  })

  it('flags a non-RiskTier defaultTier as not total', () => {
    const bad = makePolicy(DEFAULT_POLICY.tierRules, { defaultTier: 7 as RiskTier })
    const a = analyzePolicy(bad)
    expect(a.total).toBe(false)
    expect(a.conflictFree).toBe(false)
    expect(a.diagnostics.some((d) => d.code === 'invalid-tier')).toBe(true)
  })
})

describe('GOV-POLICY-ALGEBRA — order-independence is permutation-invariance', () => {
  const fullShuffle = fc.shuffledSubarray([...DEFAULT_POLICY.tierRules], {
    minLength: DEFAULT_POLICY.tierRules.length,
    maxLength: DEFAULT_POLICY.tierRules.length,
  })

  it('a certified order-independent policy yields identical tiers under ANY rule permutation', () => {
    expect(analyzePolicy(DEFAULT_POLICY).orderIndependent).toBe(true)
    fc.assert(
      fc.property(fullShuffle, arbType, (perm, t) => {
        const permuted = makePolicy(perm)
        expect(tierOf(intentOf(t), permuted)).toBe(tierOf(intentOf(t), DEFAULT_POLICY))
      }),
      FC,
    )
  })

  it('an order-DEPENDENT policy is flagged, and reordering provably changes a decision', () => {
    // general 'data'@0 then specific 'data.delete'@2 — overlapping namespaces, differing tiers.
    const general = makePolicy([
      { prefix: 'data', tier: 0 },
      { prefix: 'data.delete', tier: 2 },
    ])
    const reversed = makePolicy([
      { prefix: 'data.delete', tier: 2 },
      { prefix: 'data', tier: 0 },
    ])
    expect(analyzePolicy(general).orderIndependent).toBe(false)
    expect(analyzePolicy(reversed).orderIndependent).toBe(false)
    // The reorder changes the decision for data.delete — order IS load-bearing here.
    expect(tierOf(intentOf('data.delete'), general)).toBe(0) // shadowed: intended tier-2 lost
    expect(tierOf(intentOf('data.delete'), reversed)).toBe(2)
  })
})

describe('GOV-POLICY-ALGEBRA — conflict-freedom (shadows, duplicates, deny/transform)', () => {
  it('detects a rule shadowed by an earlier, more-general rule with a different tier', () => {
    const shadowed = makePolicy([
      { prefix: 'data', tier: 0 },
      { prefix: 'data.delete', tier: 2 }, // unreachable
    ])
    const a = analyzePolicy(shadowed)
    expect(a.conflictFree).toBe(false)
    expect(a.diagnostics.some((d) => d.code === 'shadowed-rule')).toBe(true)
    expect(() => assertWellFormedPolicy(shadowed)).toThrow(/ill-formed policy/)
  })

  it('the intended specific-over-general order is NOT a conflict (reachable), only order-dependent', () => {
    const ok = makePolicy([
      { prefix: 'data.delete', tier: 2 }, // specific first → reachable
      { prefix: 'data', tier: 0 },
    ])
    const a = analyzePolicy(ok)
    expect(a.conflictFree).toBe(true) // no shadow: data.delete is reachable
    expect(a.orderIndependent).toBe(false) // but order still matters
    expect(tierOf(intentOf('data.delete'), ok)).toBe(2)
  })

  it('detects a duplicate prefix', () => {
    const dup = makePolicy([
      { prefix: 'payment.', tier: 2 },
      { prefix: 'payment.', tier: 3 },
    ])
    const a = analyzePolicy(dup)
    expect(a.diagnostics.some((d) => d.code === 'duplicate-prefix')).toBe(true)
    expect(a.conflictFree).toBe(false)
  })

  it('detects an action that is both denied and transformed (deny wins, transform dead)', () => {
    const clash = makePolicy(DEFAULT_POLICY.tierRules, {
      denyActions: ['payment.transfer'],
      transformActions: ['payment.transfer'],
    })
    const a = analyzePolicy(clash)
    expect(a.diagnostics.some((d) => d.code === 'deny-transform-conflict')).toBe(true)
    expect(a.conflictFree).toBe(false)
  })

  it('a near-prefix sibling is NOT falsely flagged (segment-wise, PS-KERNEL-03)', () => {
    // data.read and data.readX are siblings; neither covers the other → no conflict.
    const siblings = makePolicy([
      { prefix: 'data.read', tier: 0 },
      { prefix: 'data.readX', tier: 2 },
    ])
    const a = analyzePolicy(siblings)
    expect(a.conflictFree).toBe(true)
    expect(a.orderIndependent).toBe(true)
  })
})

describe('GOV-POLICY-ALGEBRA — fault-injection: the checker catches injected shadow faults', () => {
  it('100% of injected general-before-specific shadow faults are caught', () => {
    // For each finance-ish specific rule, inject a more-general ancestor at a different tier
    // ahead of it; the analyzer must flag a shadowed-rule every time.
    const specifics: ReadonlyArray<readonly [string, string, RiskTier, RiskTier]> = [
      ['data', 'data.delete', 0, 2],
      ['payment', 'payment.transfer', 1, 2],
      ['infra', 'infra.deploy', 0, 2],
      ['model', 'model.weights', 1, 3],
      ['actuation', 'actuation.physical', 0, 3],
    ]
    let caught = 0
    for (const [gen, spec, genTier, specTier] of specifics) {
      const faulted = makePolicy([
        { prefix: gen, tier: genTier },
        { prefix: spec, tier: specTier },
      ])
      const a = analyzePolicy(faulted)
      if (!a.conflictFree && a.diagnostics.some((d) => d.code === 'shadowed-rule')) caught++
    }
    expect(caught).toBe(specifics.length) // MEASURED: 5/5 injected faults caught
  })
})

describe('GOV-POLICY-ALGEBRA — council-fix hardening', () => {
  it('flags prefixes with an empty namespace segment, but allows a trailing-dot namespace marker', () => {
    const hasMalformed = (rules: readonly TierRule[]): boolean =>
      analyzePolicy(makePolicy(rules)).diagnostics.some((d) => d.code === 'malformed-prefix')
    expect(hasMalformed([{ prefix: 'data..x', tier: 0 }])).toBe(true) // consecutive dots
    expect(hasMalformed([{ prefix: '.data', tier: 0 }])).toBe(true) // leading dot
    expect(hasMalformed([{ prefix: '', tier: 0 }])).toBe(true) // empty
    // trailing dot is a VALID namespace marker (DEFAULT_POLICY uses 'payment.' / 'draft.') — not flagged
    expect(hasMalformed([{ prefix: 'payment.', tier: 2 }])).toBe(false)
    expect(
      analyzePolicy(DEFAULT_POLICY).diagnostics.some((d) => d.code === 'malformed-prefix'),
    ).toBe(false)
  })

  it('a missing / undefined default tier is reported as not total', () => {
    const noDefault = makePolicy(DEFAULT_POLICY.tierRules, {
      defaultTier: undefined as unknown as RiskTier,
    })
    const a = analyzePolicy(noDefault)
    expect(a.total).toBe(false)
    expect(a.diagnostics.some((d) => d.code === 'invalid-tier')).toBe(true)
  })

  it('EXHAUSTIVE: every permutation of a certified order-independent 4-rule policy gives identical tiers', () => {
    const rules: TierRule[] = [
      { prefix: 'data.read', tier: 0 },
      { prefix: 'payment.', tier: 2 },
      { prefix: 'infra.deploy', tier: 2 },
      { prefix: 'model.weights', tier: 3 },
    ]
    const base = makePolicy(rules)
    expect(analyzePolicy(base).orderIndependent).toBe(true)
    const types = ['data.read', 'payment.transfer', 'infra.deploy', 'model.weights.x', 'unknown']
    const expected = types.map((t) => tierOf(intentOf(t), base))
    let count = 0
    for (const perm of permutations(rules)) {
      const p = makePolicy(perm)
      types.forEach((t, k) => expect(tierOf(intentOf(t), p)).toBe(expected[k]))
      count++
    }
    expect(count).toBe(24) // 4! — ALL permutations checked, not sampled
  })
})
