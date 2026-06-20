// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { TransparencyLog, checkInclusion } from '../../translog/src/index.js'
import { buildCbom, signCbom, verifyCbom, cbomLeaf } from '../src/index.js'

const SUITE = SUITE_IDS.PS_5
const s = signerFor(SUITE)

describe('Cryptographic Bill of Materials (CBOM)', () => {
  it('inventories the active suites and flags the quantum-vulnerable hybrid legs', () => {
    const cbom = buildCbom(1_750_000_000)
    const names = cbom.assets.map((a) => a.name)
    expect(names).toContain('ML-DSA-87')
    expect(names).toContain('ML-KEM-1024')
    // the classical hybrid legs are flagged quantum-vulnerable (Shor); ML-KEM is not
    expect(cbom.quantumVulnerable).toContain('P-384')
    expect(cbom.quantumVulnerable).toContain('X25519')
    expect(cbom.quantumVulnerable).not.toContain('ML-KEM-1024')
  })

  it('records each active suite with its CNSA 2.0 level', () => {
    const cbom = buildCbom()
    const ps5 = cbom.suites.find((x) => x.suiteId === SUITE_IDS.PS_5)!
    const ps1 = cbom.suites.find((x) => x.suiteId === SUITE_IDS.PS_1)!
    expect(ps5.cnsaLevel).toBe('CNSA-2.0-Cat5-transitional')
    expect(ps1.cnsaLevel).toBe('non-conformant')
  })

  it('is deterministic (no ambient clock; sorted assets/suites)', () => {
    expect(JSON.stringify(buildCbom(5))).toBe(JSON.stringify(buildCbom(5)))
  })

  it('signs, verifies under the issuer key, rejects a wrong key and a wrong context', () => {
    const issuer = s.keygen()
    const env = signCbom(buildCbom(1), SUITE, issuer.secretKey)
    expect(verifyCbom(env, issuer.publicKey)).toBe(true)
    expect(verifyCbom(env, s.keygen().publicKey)).toBe(false)
    expect(verifyCbom({ ...env, context: 'x' }, issuer.publicKey)).toBe(false)
  })

  it('anchors in the transparency log with a verifiable inclusion proof', () => {
    const issuer = s.keygen()
    const env = signCbom(buildCbom(), SUITE, issuer.secretKey)
    const log = new TransparencyLog()
    const { index } = log.append(cbomLeaf(env))
    expect(checkInclusion(log.proveInclusion(index), log.root())).toBe(true)
  })

  it('every quantum-vulnerable leg carries a Shor-broken deprecation note', () => {
    const vuln = buildCbom().assets.filter((a) => a.quantum === 'quantum-vulnerable')
    expect(vuln.length).toBeGreaterThan(0)
    expect(vuln.every((a) => a.deprecation.includes('Shor-broken'))).toBe(true)
  })
})
