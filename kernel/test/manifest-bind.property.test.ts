// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * GOV-MANIFEST-BIND — tests that the Action-Manifest's self-asserted riskClass / policyHash are
 * bound to the kernel's actually-applied tier / evaluator identity, so verbId↔tier "semantic
 * laundering" (relabelling a T2 action as T0) and policy mismatch are rejected.
 */

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import {
  DEFAULT_POLICY,
  evaluatorVersion,
  expectedRiskClass,
  expectedPolicyBinding,
  checkManifestConsistency,
  assertManifestConsistent,
} from '../src/index.js'
import type { ActionIntent } from '../../capabilities/src/index.js'
import type { ActionManifest, RiskClass } from '../../capabilities/src/profile.js'

const PAY: ActionIntent = {
  type: 'payment.transfer',
  resource: 'acct://t',
  counterparty: 'a',
  amount: 10,
} // tier 2
const READ: ActionIntent = { type: 'data.read', resource: 'doc://x' } // tier 0
const DEPLOY: ActionIntent = { type: 'infra.deploy', resource: 'r' } // tier 2
const ARM: ActionIntent = { type: 'actuation.physical.arm', resource: 'r' } // tier 3

const ALL_RISK: readonly RiskClass[] = ['T0', 'T1', 'T2', 'T3']

const manifestFor = (intent: ActionIntent, over: Partial<ActionManifest> = {}): ActionManifest => ({
  verbId: 'fin.payment.transfer',
  authorityScope: 'acct://t',
  riskClass: expectedRiskClass(intent, DEFAULT_POLICY),
  policyHash: expectedPolicyBinding(DEFAULT_POLICY),
  replayDomain: 'd',
  expiry: 10_000_000_000,
  ...over,
})

describe('GOV-MANIFEST-BIND — expected bindings track the kernel decision', () => {
  it('riskClass = T${tierOf}; policyHash = domain-separated policy hash (kernel-version-independent)', () => {
    expect(expectedRiskClass(READ, DEFAULT_POLICY)).toBe('T0')
    expect(expectedRiskClass(PAY, DEFAULT_POLICY)).toBe('T2')
    expect(expectedRiskClass(DEPLOY, DEFAULT_POLICY)).toBe('T2')
    expect(expectedRiskClass(ARM, DEFAULT_POLICY)).toBe('T3')
    const pb = expectedPolicyBinding(DEFAULT_POLICY)
    expect(pb).toMatch(/^[0-9a-f]{64}$/) // SHA3-256 hex
    expect(pb).toBe(expectedPolicyBinding(DEFAULT_POLICY)) // deterministic
    expect(pb).not.toBe(evaluatorVersion(DEFAULT_POLICY)) // decoupled from the kernel identity (council fix)
  })
})

describe('GOV-MANIFEST-BIND — a consistent manifest passes', () => {
  it('matching riskClass + policyHash → consistent', () => {
    const r = checkManifestConsistency(manifestFor(PAY), PAY, DEFAULT_POLICY)
    expect(r.consistent).toBe(true)
    expect(r.mismatches).toEqual([])
    expect(() => assertManifestConsistent(manifestFor(PAY), PAY, DEFAULT_POLICY)).not.toThrow()
  })
})

describe('GOV-MANIFEST-BIND — laundering and policy mismatch are caught', () => {
  it('a T2 payment relabelled as a lower risk class is rejected', () => {
    const laundered = manifestFor(PAY, { riskClass: 'T0' })
    const r = checkManifestConsistency(laundered, PAY, DEFAULT_POLICY)
    expect(r.consistent).toBe(false)
    expect(r.mismatches.some((m) => m.includes('riskClass'))).toBe(true)
    expect(() => assertManifestConsistent(laundered, PAY, DEFAULT_POLICY)).toThrow(/inconsistent/)
  })

  it('a wrong policyHash is rejected', () => {
    const wrong = manifestFor(PAY, { policyHash: 'polarseek-kernel/0.1.0+deadbeefdeadbeef' })
    const r = checkManifestConsistency(wrong, PAY, DEFAULT_POLICY)
    expect(r.consistent).toBe(false)
    expect(r.mismatches.some((m) => m.includes('policyHash'))).toBe(true)
  })

  it('fault-injection: every WRONG riskClass is caught (100%)', () => {
    const cases: ReadonlyArray<readonly [ActionIntent, RiskClass]> = [
      [READ, 'T0'],
      [PAY, 'T2'],
      [DEPLOY, 'T2'],
      [ARM, 'T3'],
    ]
    let caught = 0
    let attempts = 0
    for (const [intent, correct] of cases) {
      for (const rc of ALL_RISK) {
        if (rc === correct) continue
        attempts++
        const r = checkManifestConsistency(
          manifestFor(intent, { riskClass: rc }),
          intent,
          DEFAULT_POLICY,
        )
        if (!r.consistent && r.mismatches.some((m) => m.includes('riskClass'))) caught++
      }
    }
    expect(attempts).toBe(12) // 4 intents × 3 wrong classes each
    expect(caught).toBe(attempts) // MEASURED: 12/12 laundering attempts caught
  })

  it('property: consistent IFF the manifest declares the true applied tier', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(READ, PAY, DEPLOY, ARM),
        fc.constantFrom(...ALL_RISK),
        (intent, rc) => {
          const m = manifestFor(intent, { riskClass: rc })
          const r = checkManifestConsistency(m, intent, DEFAULT_POLICY)
          expect(r.consistent).toBe(rc === expectedRiskClass(intent, DEFAULT_POLICY))
        },
      ),
      { seed: 0x676d62, numRuns: 100 },
    )
  })
})
