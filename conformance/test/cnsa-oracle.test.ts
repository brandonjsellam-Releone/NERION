// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS, getSuite } from '../../crypto/src/index.js'
import type { Suite } from '../../crypto/src/index.js'
import { TransparencyLog, checkInclusion } from '../../translog/src/index.js'
import { assertCnsa, signCnsaVerdict, verifyCnsaVerdict, cnsaVerdictLeaf } from '../src/index.js'

const SUITE = SUITE_IDS.PS_5
const s = signerFor(SUITE)

describe('signed CNSA 2.0 conformance verdict', () => {
  it('PS-5 verdict is conformant + transitional (hybrid KEM + SHA3 advisory, all WARN)', () => {
    const v = assertCnsa(SUITE_IDS.PS_5)
    expect(v.conformant).toBe(true)
    expect(v.level).toBe('CNSA-2.0-Cat5-transitional')
    expect(v.findings.length).toBeGreaterThan(0)
    expect(v.findings.every((f) => f.severity === 'WARN')).toBe(true)
    expect(v.findings.some((f) => f.fieldPath === 'kemId')).toBe(true)
  })

  it('PS-1 verdict is non-conformant (ML-KEM-768 is a HARD finding)', () => {
    const v = assertCnsa(SUITE_IDS.PS_1)
    expect(v.conformant).toBe(false)
    expect(v.level).toBe('non-conformant')
    expect(v.findings.some((f) => f.fieldPath === 'kemId' && f.severity === 'HARD')).toBe(true)
  })

  it('signs, verifies under the issuer key, and rejects a wrong key (+ context-bound)', () => {
    const issuer = s.keygen()
    const env = signCnsaVerdict(assertCnsa(SUITE_IDS.PS_5, 1_750_000_000), SUITE, issuer.secretKey)
    expect(verifyCnsaVerdict(env, issuer.publicKey)).toBe(true)
    expect(verifyCnsaVerdict(env, s.keygen().publicKey)).toBe(false)
    // wrong context is rejected even with the right key
    expect(verifyCnsaVerdict({ ...env, context: 'other' }, issuer.publicKey)).toBe(false)
  })

  it('anchors in the transparency log with a verifiable inclusion proof', () => {
    const issuer = s.keygen()
    const env = signCnsaVerdict(assertCnsa(SUITE_IDS.PS_5), SUITE, issuer.secretKey)
    const log = new TransparencyLog()
    const { index } = log.append(cnsaVerdictLeaf(env))
    expect(checkInclusion(log.proveInclusion(index), log.root())).toBe(true)
  })

  it('a synthetic non-CNSA suite (FN-DSA signature) is non-conformant (non-vacuous)', () => {
    const synthetic: Suite = { ...getSuite(SUITE_IDS.PS_5), sigId: 'FN-DSA-1024' }
    const v = assertCnsa(synthetic)
    expect(v.conformant).toBe(false)
    expect(v.findings.some((f) => f.fieldPath === 'sigId' && f.severity === 'HARD')).toBe(true)
  })
})
