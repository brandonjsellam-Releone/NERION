// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  getCodeSigner,
  assertSingleTree,
  implementedCodeSigIds,
  CODE_SIG_IDS,
  NotImplementedError,
  PolicyError,
  type HbsParams,
} from '../src/index.js'

const single = (over: Partial<HbsParams> = {}): HbsParams => ({
  family: 'LMS',
  multiTree: false,
  hash: 'SHA-256/192',
  height: 15,
  ...over,
})

describe('CNSA 2.0 code-signing (stateful HBS) policy + gated stub', () => {
  it('getCodeSigner throws NotImplementedError (hardware-module-only; never home-rolled)', () => {
    expect(() => getCodeSigner(CODE_SIG_IDS.LMS_SHA256_M24)).toThrow(NotImplementedError)
    expect(implementedCodeSigIds()).toEqual([])
  })

  it('assertSingleTree accepts single-tree LMS and XMSS', () => {
    expect(() => assertSingleTree(single())).not.toThrow()
    expect(() => assertSingleTree(single({ family: 'XMSS' }))).not.toThrow()
  })

  it('assertSingleTree rejects multi-tree (HSS / XMSS^MT) per CNSA 2.0', () => {
    expect(() => assertSingleTree(single({ multiTree: true }))).toThrow(PolicyError)
    // defensive: a multi-tree id even with multiTree:false is rejected
    expect(() => assertSingleTree(single(), 'LMS-HSS-L2')).toThrow(PolicyError)
    expect(() => assertSingleTree(single(), 'XMSSMT-SHA2_20-2_256')).toThrow(PolicyError)
  })

  it('getCodeSigner rejects a multi-tree id with a policy error (not NotImplemented)', () => {
    expect(() => getCodeSigner('XMSSMT-SHA2_20-2_256')).toThrow(PolicyError)
  })
})
