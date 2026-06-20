// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { issueRoot } from '../../capabilities/src/index.js'
import { decide, DEFAULT_POLICY, type KernelInput, type Decision } from '../../kernel/src/index.js'
import { runNegativeOracle, loadPerceptionVectors } from '../src/negative.js'

const SUITE = SUITE_IDS.PS_5
const s = signerFor(SUITE)
const NOW = 1_750_000_000

function baselineInput(): KernelInput {
  const authority = s.keygen()
  const agent = s.keygen()
  const cap = issueRoot(
    {
      subject: bytesToHex(agent.publicKey),
      actions: ['payment.transfer'],
      perActionCeiling: 1000,
      aggregateCap: null,
      counterparties: null,
      maxTier: 2,
      notBefore: 0,
      notAfter: NOW + 1000,
      delegable: false,
    },
    SUITE,
    authority,
  )
  return {
    intent: { type: 'payment.transfer', resource: 'acct://x', amount: 500 },
    capabilities: [cap],
    policy: DEFAULT_POLICY,
    trustedRoots: [authority.publicKey],
    now: NOW,
    observedAggregate: 0,
    holder: bytesToHex(agent.publicKey),
  }
}

describe('govern-the-verb negative oracle', () => {
  it('the kernel decision is invariant to all perception-shaped side-data (allow case)', () => {
    const v = runNegativeOracle(baselineInput())
    expect(v.invariant).toBe(true)
    expect(v.fieldsTested).toBeGreaterThan(15)
    expect(v.divergences).toEqual([])
  })

  it('invariant on a deny case too (no capability)', () => {
    const input = { ...baselineInput(), capabilities: [] }
    expect(decide(input).effect).toBe('deny')
    expect(runNegativeOracle(input).invariant).toBe(true)
  })

  it('the vector names the forbidden perception primitives (the fence is meaningful)', () => {
    const fields = loadPerceptionVectors()
    expect(Object.keys(fields).length).toBeGreaterThan(15)
    expect('camera' in fields && 'frameSequence' in fields && 'faceVector' in fields).toBe(true)
  })

  it('is NOT vacuous: it CATCHES a kernel that peeks at perception', () => {
    // a "govern-the-eye" kernel that lets a face vector flip the verdict
    const leaky = (i: KernelInput): Decision => {
      const base = decide(i)
      if (i.intent.params && 'faceVector' in i.intent.params) {
        return { ...base, effect: 'deny', reasons: ['blocked by face match'] }
      }
      return base
    }
    const v = runNegativeOracle(baselineInput(), leaky)
    expect(v.invariant).toBe(false)
    expect(v.divergences.some((d) => d.field === 'faceVector')).toBe(true)
  })
})
