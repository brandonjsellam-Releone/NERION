// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * GOV-PARAMS-BLINDNESS — unbounded, adversarial witness that the admission decision
 * never reads `intent.params` (govern the verb, never the eye; ADR-0007).
 *
 * Strictly stronger than the finite negative-oracle vector set: a property test over
 * arbitrary `params` on the allow / deny / denylist / transform paths, a factoring test
 * through `governedView`, and compile-time witnesses that the governed view structurally
 * excludes `params`. Fixed fast-check seed → reproducible.
 */

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { issueRoot } from '../../capabilities/src/index.js'
import type { ActionIntent } from '../../capabilities/src/index.js'
import { decide, DEFAULT_POLICY, governedView } from '../src/index.js'
import type { GovernedIntent, KernelInput } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)
const authority = signer.keygen()
const holder = signer.keygen()
const holderHex = bytesToHex(holder.publicKey)

const root = issueRoot(
  {
    subject: holderHex,
    actions: ['payment.transfer', 'data.read'],
    perActionCeiling: null,
    aggregateCap: null,
    counterparties: null,
    maxTier: 3,
    notBefore: 0,
    notAfter: 10_000_000_000,
    delegable: false,
  },
  suite,
  authority,
)

const input = (intent: ActionIntent, over: Partial<KernelInput> = {}): KernelInput => ({
  intent,
  capabilities: [root],
  policy: DEFAULT_POLICY,
  trustedRoots: [authority.publicKey],
  now: 1000,
  observedAggregate: 0,
  holder: holderHex,
  ...over,
})

const PAY: ActionIntent = {
  type: 'payment.transfer',
  resource: 'acct://t',
  counterparty: 'a',
  amount: 10,
}
const READ: ActionIntent = { type: 'data.read', resource: 'doc://x' }

const withParams = (intent: ActionIntent, params: Record<string, unknown>): ActionIntent => ({
  ...intent,
  params,
})

// Arbitrary params: arbitrary nested/typed/huge values under arbitrary string keys.
// (decide() reads NONE of params, so even keys that collide with governed field names
//  cannot matter — that collision case is also asserted explicitly below.)
const arbParams = fc.dictionary(fc.string(), fc.anything())

// Fixed seed → the property run is reproducible (the harness ethos: measured, re-runnable).
const FC = { seed: 0x6e72696f, numRuns: 200 } as const

describe('GOV-PARAMS-BLINDNESS — decide() is invariant under intent.params', () => {
  const cases: ReadonlyArray<readonly [string, ActionIntent, Partial<KernelInput>]> = [
    ['allow T2 payment', PAY, {}],
    ['allow T0 read', READ, {}],
    ['deny (no capability)', PAY, { capabilities: [] }],
    ['deny (denylist)', PAY, { policy: { ...DEFAULT_POLICY, denyActions: ['payment.transfer'] } }],
    [
      'transform (policy)',
      READ,
      { policy: { ...DEFAULT_POLICY, transformActions: ['data.read'] } },
    ],
  ]

  for (const [name, intent, over] of cases) {
    it(`${name}: arbitrary params never change the Decision`, () => {
      const baseline = decide(input(intent, over))
      fc.assert(
        fc.property(arbParams, (params) => {
          expect(decide(input(withParams(intent, params), over))).toEqual(baseline)
        }),
        FC,
      )
    })
  }

  it('params whose keys collide with governed field names are still ignored', () => {
    const adversarial: Record<string, unknown> = {
      type: 'data.read', // try to relabel the verb via params
      amount: 0, // try to zero the amount via params
      counterparty: 'someone-else',
      resource: 'acct://attacker',
      tier: 0,
      nested: { allow: true, __proto__: { polluted: true } },
      big: Number.MAX_SAFE_INTEGER,
    }
    expect(decide(input(withParams(PAY, adversarial)))).toEqual(decide(input(PAY)))
  })

  it('decide() factors through governedView: equal governed views ⇒ equal Decisions', () => {
    fc.assert(
      fc.property(arbParams, arbParams, (p1, p2) => {
        const a = withParams(PAY, p1)
        const b = withParams(PAY, p2)
        expect(governedView(a)).toEqual(governedView(b)) // params dropped → views equal
        expect(decide(input(a))).toEqual(decide(input(b)))
      }),
      FC,
    )
  })

  it('governedView strips params and preserves every governed field', () => {
    const v = governedView(withParams(PAY, { secret: 'perception', amount: 999_999 }))
    expect(v).toEqual({
      type: 'payment.transfer',
      resource: 'acct://t',
      counterparty: 'a',
      amount: 10,
    })
    expect('params' in v).toBe(false)
  })
})

// ---- Compile-time witnesses (checked by `npm run typecheck`) ----------------------------
// These FAIL TO COMPILE if the governed view ever gains `params` or drifts from the
// explicit governed-field allowlist — turning a silent invariant regression into a build error.
type _Assert<T extends true> = T
type _Equal<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false

// 1. `params` is structurally absent from the governed view.
type _NoParams = _Assert<_Equal<'params' extends keyof GovernedIntent ? true : false, false>>
// 2. The governed key set is EXACTLY the allowlist (adding a field to ActionIntent breaks this).
type _Keys = _Assert<_Equal<keyof GovernedIntent, 'type' | 'resource' | 'counterparty' | 'amount'>>

export type __ParamsBlindWitness = [_NoParams, _Keys]
