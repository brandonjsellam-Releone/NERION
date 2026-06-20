// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { assessCnsa20, getSuite, SUITE_IDS } from '../src/index.js'
import type { Suite } from '../src/index.js'

const sig = (s: ReturnType<typeof assessCnsa20>) =>
  s.findings.find((f) => f.component === 'signature')!
const kem = (s: ReturnType<typeof assessCnsa20>) => s.findings.find((f) => f.component === 'kem')!

describe('CNSA 2.0 conformance oracle', () => {
  it('PS-5 (Cat-5) is CNSA 2.0 conformant but TRANSITIONAL (hybrid KEM + SHA3 hashing)', () => {
    const a = assessCnsa20(getSuite(SUITE_IDS.PS_5))
    expect(a.conformant).toBe(true)
    expect(a.pureCnsa).toBe(false) // ML-KEM-1024+P-384 hybrid + SHA3/SHAKE are transitional
    expect(sig(a).status).toBe('conformant') // ML-DSA-87
    expect(kem(a).status).toBe('transitional') // ML-KEM-1024 in a P-384 hybrid
    expect(a.findings.find((f) => f.component === 'symmetric')!.status).toBe('conformant') // AES-256
  })

  it('PS-1 (transition tier) is NOT CNSA 2.0 (ML-KEM-768 is not approved)', () => {
    const a = assessCnsa20(getSuite(SUITE_IDS.PS_1))
    expect(a.conformant).toBe(false)
    expect(kem(a).status).toBe('non-conformant')
  })

  it('flags SLH-DSA and Falcon/FN-DSA as EXCLUDED from CNSA 2.0', () => {
    const base = getSuite(SUITE_IDS.PS_5)
    const slh: Suite = { ...base, sigId: 'SLH-DSA-SHAKE-256f' }
    const fn: Suite = { ...base, sigId: 'FN-DSA-1024' }
    expect(sig(assessCnsa20(slh)).status).toBe('non-conformant')
    expect(sig(assessCnsa20(fn)).status).toBe('non-conformant')
    expect(assessCnsa20(slh).conformant).toBe(false)
  })

  it('a pure CNSA 2.0 suite (ML-KEM-1024 alone, SHA-384 hashing) is pureCnsa', () => {
    const base = getSuite(SUITE_IDS.PS_5)
    const pure: Suite = {
      ...base,
      kemId: 'MLKEM1024',
      hashId: 'SHA-384',
      macId: 'HMAC-SHA-384',
      aeadId: 'AES-256-GCM',
    }
    const a = assessCnsa20(pure)
    expect(a.conformant).toBe(true)
    expect(a.pureCnsa).toBe(true)
  })

  it('classifies single-tree LMS/XMSS conformant; HSS/XMSS^MT multi-tree excluded', () => {
    const base = getSuite(SUITE_IDS.PS_5)
    const lms: Suite = { ...base, sigId: 'LMS-SHA256-M24' }
    const hss: Suite = { ...base, sigId: 'LMS-HSS-L2' }
    const xmssmt: Suite = { ...base, sigId: 'XMSSMT-SHA2_20-2_256' }
    expect(sig(assessCnsa20(lms)).status).toBe('conformant')
    expect(sig(assessCnsa20(hss)).status).toBe('non-conformant')
    expect(sig(assessCnsa20(xmssmt)).status).toBe('non-conformant')
  })
})
