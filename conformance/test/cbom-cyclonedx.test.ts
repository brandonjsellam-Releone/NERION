// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { buildCbom } from '../src/cbom.js'
import { toCycloneDx } from '../src/index.js'

describe('CycloneDX 1.6 CBOM projection (TNO Handbook p.34-35, p.114)', () => {
  it('emits CycloneDX 1.6 cryptographic-asset components', () => {
    const cdx = toCycloneDx(buildCbom(1_750_000_000))
    expect(cdx.bomFormat).toBe('CycloneDX')
    expect(cdx.specVersion).toBe('1.6')
    expect(cdx.components.length).toBeGreaterThan(0)
    expect(cdx.components.every((c) => c.type === 'cryptographic-asset')).toBe(true)
    const mlkem = cdx.components.find((c) => c.name === 'ML-KEM-1024')!
    expect(mlkem.cryptoProperties.assetType).toBe('algorithm')
    expect(mlkem.cryptoProperties.algorithmProperties.primitive).toBe('kem')
    expect(mlkem.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel).toBe(5)
    expect(mlkem.cryptoProperties.algorithmProperties.cryptoFunctions).toContain('encapsulate')
    // A1 size enrichment flows through as CycloneDX properties.
    expect(
      mlkem.properties.some((p) => p.name === 'nerion:size:publicKeyBytes' && p.value === '1568'),
    ).toBe(true)
  })

  it('maps key-exchange legs to keyagree with quantum level 0', () => {
    const cdx = toCycloneDx(buildCbom())
    const p384 = cdx.components.find((c) => c.name === 'P-384')!
    expect(p384.cryptoProperties.algorithmProperties.primitive).toBe('keyagree')
    expect(p384.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel).toBe(0)
    expect(cdx.metadata.properties.some((p) => p.value.includes('P-384'))).toBe(true)
  })

  it('is deterministic', () => {
    expect(JSON.stringify(toCycloneDx(buildCbom(5)))).toBe(
      JSON.stringify(toCycloneDx(buildCbom(5))),
    )
  })
})
