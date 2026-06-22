// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  SUITE_IDS,
  getSuite,
  allSuites,
  activeSuiteIds,
  negotiate,
  kemFor,
  signerFor,
} from '../src/suites.js'
import { UnknownSuiteError, NoCommonSuiteError, NotImplementedError } from '../src/errors.js'
import fc from 'fast-check'

describe('SuiteID registry', () => {
  it('has both active tiers and resolves their primitives', () => {
    const active = activeSuiteIds()
    expect(active).toContain(SUITE_IDS.PS_1)
    expect(active).toContain(SUITE_IDS.PS_5)
    // PS-5 is preferred over PS-1.
    expect(active[0]).toBe(SUITE_IDS.PS_5)
    expect(kemFor(SUITE_IDS.PS_5).id).toBe('MLKEM1024-P384')
    expect(signerFor(SUITE_IDS.PS_5).id).toBe('ML-DSA-87')
  })

  it('excludes pending/non-active suites from negotiation', () => {
    const active = activeSuiteIds()
    expect(active).not.toContain(SUITE_IDS.PS_5_HQC)
    expect(active).not.toContain(SUITE_IDS.PS_5_FN)
    expect(getSuite(SUITE_IDS.PS_5_HQC).status).toBe('pending-standardization')
    expect(getSuite(SUITE_IDS.PS_5_FN).status).toBe('not-load-bearing')
  })

  it('every registered suite has a category and a description', () => {
    for (const s of allSuites()) {
      expect([1, 3, 5]).toContain(s.category)
      expect(s.description.length).toBeGreaterThan(0)
      expect(s.standards.length).toBeGreaterThan(0)
    }
  })

  it('negotiate picks the most-preferred mutually-supported active suite', () => {
    expect(negotiate([SUITE_IDS.PS_1, SUITE_IDS.PS_5], [SUITE_IDS.PS_5, SUITE_IDS.PS_1])).toBe(
      SUITE_IDS.PS_5,
    )
    expect(negotiate([SUITE_IDS.PS_1], [SUITE_IDS.PS_1, SUITE_IDS.PS_5])).toBe(SUITE_IDS.PS_1)
  })

  it('negotiate never selects a pending suite even if both offer it', () => {
    expect(() => negotiate([SUITE_IDS.PS_5_HQC], [SUITE_IDS.PS_5_HQC])).toThrow(NoCommonSuiteError)
  })

  it('downgrade-resistant: over random suite-set pairs, negotiate yields the most-preferred ACTIVE common suite or rejects (TNO p.63/67)', () => {
    const allIds = allSuites().map((s) => s.id)
    const active = activeSuiteIds() // most-preferred first
    fc.assert(
      fc.property(fc.subarray(allIds), fc.subarray(allIds), (local, remote) => {
        const commonActive = active.filter((id) => local.includes(id) && remote.includes(id))
        let result: string
        try {
          result = negotiate(local, remote)
        } catch (e) {
          // the ONLY permitted failure is "no common active suite" — a downgrade is never silently chosen
          expect(e).toBeInstanceOf(NoCommonSuiteError)
          expect(commonActive.length).toBe(0)
          return
        }
        // a returned suite must be ACTIVE, mutually supported, and the HIGHEST-preference such suite
        expect(getSuite(result).status).toBe('active')
        expect(local.includes(result) && remote.includes(result)).toBe(true)
        expect(result).toBe(commonActive[0])
      }),
      { numRuns: 300 },
    )
  })

  it('throws on unknown suite id', () => {
    expect(() => getSuite('PS-999')).toThrow(UnknownSuiteError)
  })

  it('resolving a pending suite primitive fails loudly', () => {
    expect(() => kemFor(SUITE_IDS.PS_5_HQC)).toThrow(NotImplementedError)
    expect(() => signerFor(SUITE_IDS.PS_5_FN)).toThrow(NotImplementedError)
  })
})
