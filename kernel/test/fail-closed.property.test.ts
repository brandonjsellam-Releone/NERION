// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * SAF-3 — fail-closed (default-deny) witness for the admission kernel.
 *
 * Two properties, both checked against an INDEPENDENT correctness oracle (council fix — a mere
 * "non-deny ⟹ authorizer present" invariant is necessary but NOT sufficient: it would still pass if
 * the kernel wrongly ALLOWED an expired/revoked/wrong-holder cap):
 *
 *   - SAFETY (no fail-open):  the decision is `deny` whenever the spec removes authorization.
 *   - LIVENESS (no wrongful deny): the decision is non-`deny` only when the spec authorizes it.
 *   - CONSISTENCY: non-`deny` ⟺ a verified authorizing capability is returned.
 *
 * `shouldDeny()` mirrors the authorization spec (capabilities/grant.ts resolver + kernel) enumerated
 * independently, so `(effect === 'deny') === shouldDeny(input)` catches a fail-open OR a wrongful deny.
 * A strong property + exhaustive witness, NOT a machine-checked proof (prover toolchain absent; see
 * GOV-NI-PROOF / SAF-1). Additive: tests only; the kernel is unchanged.
 */

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { issueRoot } from '../../capabilities/src/index.js'
import type { ActionIntent } from '../../capabilities/src/index.js'
import { decide, decideWithAuthorizer, DEFAULT_POLICY } from '../src/index.js'
import type { KernelInput, Policy } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)
const authority = signer.keygen()
const holder = signer.keygen()
const holderHex = bytesToHex(holder.publicKey)

const PER_ACTION_CEILING = 1000
const NOT_AFTER = 10_000_000_000
const CAP_ACTIONS = new Set(['payment.transfer', 'data.read'])

const root = issueRoot(
  {
    subject: holderHex,
    actions: [...CAP_ACTIONS],
    perActionCeiling: PER_ACTION_CEILING,
    aggregateCap: null,
    counterparties: null,
    maxTier: 3,
    notBefore: 0,
    notAfter: NOT_AFTER,
    delegable: false,
  },
  suite,
  authority,
)
const rootId = root.chain[0]!.grant.id

const baseInput = (intent: ActionIntent, over: Partial<KernelInput> = {}): KernelInput => ({
  intent,
  capabilities: [root],
  policy: DEFAULT_POLICY,
  trustedRoots: [authority.publicKey],
  now: 1000,
  observedAggregate: 0,
  holder: holderHex,
  ...over,
})

interface Gen {
  readonly type: string
  readonly amount: number
  readonly now: number
  readonly observedAggregate: number
  readonly withCap: boolean
  readonly rightHolder: boolean
  readonly denylisted: boolean
  readonly transformlisted: boolean
  readonly revokeRoot: boolean
}

const safeInt = (n: number): boolean => Number.isSafeInteger(n)

/**
 * Independent spec oracle: the input MUST be denied iff any condition below removes authorization.
 * Enumerated from the authorization spec (resolver + grant.ts + kernel), NOT from the kernel impl,
 * so a divergence (fail-open OR wrongful deny) surfaces as a mismatch.
 */
const shouldDeny = (g: Gen): boolean =>
  !g.withCap || // default-deny: no capability
  g.denylisted || // policy denylist (checked before resolve)
  g.revokeRoot || // revoked root id
  !g.rightHolder || // holder ≠ capability subject
  !CAP_ACTIONS.has(g.type) || // capability does not grant this action
  !safeInt(g.now) ||
  g.now < 0 ||
  g.now > NOT_AFTER || // clock / validity window guard
  !safeInt(g.amount) ||
  g.amount < 0 ||
  g.amount > PER_ACTION_CEILING || // amount guard + per-action ceiling
  !safeInt(g.observedAggregate) ||
  g.observedAggregate < 0 // aggregate guard

const arb: fc.Arbitrary<Gen> = fc.record({
  type: fc.oneof(
    fc.constantFrom(
      'payment.transfer',
      'data.read',
      'infra.deploy',
      'actuation.physical.arm',
      'unknown.x',
    ),
    fc.string(),
  ),
  amount: fc.oneof(
    fc.integer({ min: 0, max: 5000 }),
    fc.integer({ min: -100, max: -1 }),
    fc.constant(Number.NaN),
    fc.constant(Number.POSITIVE_INFINITY),
  ),
  now: fc.oneof(
    fc.integer({ min: 0, max: NOT_AFTER }),
    fc.integer({ min: NOT_AFTER + 1, max: 2 * NOT_AFTER }),
    fc.constant(Number.NaN),
    fc.constant(Number.POSITIVE_INFINITY),
    fc.integer({ min: -100, max: -1 }),
  ),
  observedAggregate: fc.oneof(fc.nat(), fc.constant(Number.NaN)),
  withCap: fc.boolean(),
  rightHolder: fc.boolean(),
  denylisted: fc.boolean(),
  transformlisted: fc.boolean(),
  revokeRoot: fc.boolean(),
})

describe('SAF-3 — fail-closed + fail-correct (correctness oracle)', () => {
  it('decision is deny IFF the spec removes authorization, and non-deny ⟺ a verified authorizer', () => {
    fc.assert(
      fc.property(arb, (g) => {
        const intent: ActionIntent = { type: g.type, resource: 'r', amount: g.amount }
        const policy: Policy = {
          ...DEFAULT_POLICY,
          denyActions: g.denylisted ? [g.type] : [],
          transformActions: g.transformlisted ? [g.type] : [],
        }
        const out = decideWithAuthorizer(
          baseInput(intent, {
            policy,
            capabilities: g.withCap ? [root] : [],
            now: g.now,
            observedAggregate: g.observedAggregate,
            holder: g.rightHolder ? holderHex : 'deadbeef',
            ...(g.revokeRoot ? { revoked: [rootId] } : {}),
          }),
        )
        const denied = out.decision.effect === 'deny'
        // SAFETY (no fail-open) + LIVENESS (no wrongful deny): exact agreement with the spec oracle.
        expect(denied).toBe(shouldDeny(g))
        // CONSISTENCY: a non-deny decision returns a verified authorizer; a deny returns none.
        expect(out.authorizingCapability === null).toBe(denied)
      }),
      { seed: 0x73616633, numRuns: 500 },
    )
  })
})

describe('SAF-3 — exhaustive lattice incl. invalid-capability deny cases', () => {
  const PAY: ActionIntent = {
    type: 'payment.transfer',
    resource: 'r',
    counterparty: 'a',
    amount: 10,
  }

  it('authorized normal action allows; transform-listed transforms — each with a non-null authorizer', () => {
    const a = decideWithAuthorizer(baseInput(PAY))
    expect(a.decision.effect).toBe('allow')
    expect(a.authorizingCapability).not.toBeNull()
    const t = decideWithAuthorizer(
      baseInput(
        { type: 'data.read', resource: 'd' },
        {
          policy: { ...DEFAULT_POLICY, transformActions: ['data.read'] },
        },
      ),
    )
    expect(t.decision.effect).toBe('transform')
    expect(t.authorizingCapability).not.toBeNull()
  })

  it.each([
    ['no capability', { capabilities: [] }],
    ['denylisted', { policy: { ...DEFAULT_POLICY, denyActions: ['payment.transfer'] } }],
    ['wrong holder', { holder: 'deadbeef' }],
    ['expired (now > notAfter)', { now: NOT_AFTER + 1 }],
    ['non-finite clock', { now: Number.NaN }],
    ['over per-action ceiling', { intentOver: { amount: PER_ACTION_CEILING + 1 } }],
    ['revoked root', { revoked: [rootId] }],
  ] as const)('invalid-cap case denies with a null authorizer: %s', (_name, over) => {
    const o = over as Partial<KernelInput> & { intentOver?: Partial<ActionIntent> }
    const intent = { ...PAY, ...(o.intentOver ?? {}) }
    const { intentOver: _drop, ...kernelOver } = o
    const out = decideWithAuthorizer(baseInput(intent, kernelOver))
    expect(out.decision.effect).toBe('deny')
    expect(out.authorizingCapability).toBeNull()
  })

  it('every exception denies at the highest tier (safe fallback, never fail-open)', () => {
    const broken = { ...DEFAULT_POLICY, tierRules: undefined as unknown as Policy['tierRules'] }
    const d = decide(baseInput(PAY, { policy: broken }))
    expect(d.effect).toBe('deny')
    expect(d.tier).toBe(3)
  })
})
