// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { buildCbom } from '../src/cbom.js'
import { toCycloneDx } from '../src/index.js'
import type { CycloneDxComponent, CycloneDxLibraryComponent } from '../src/index.js'

const cryptoComponents = (cdx: ReturnType<typeof toCycloneDx>): CycloneDxComponent[] =>
  cdx.components.filter((c): c is CycloneDxComponent => c.type === 'cryptographic-asset')

const libraryComponents = (cdx: ReturnType<typeof toCycloneDx>): CycloneDxLibraryComponent[] =>
  cdx.components.filter((c): c is CycloneDxLibraryComponent => c.type === 'library')

describe('CycloneDX 1.6 CBOM projection (TNO Handbook p.34-35, p.114)', () => {
  it('emits CycloneDX 1.6 cryptographic-asset components', () => {
    const cdx = toCycloneDx(buildCbom(1_750_000_000))
    expect(cdx.bomFormat).toBe('CycloneDX')
    expect(cdx.specVersion).toBe('1.6')
    const crypto = cryptoComponents(cdx)
    expect(crypto.length).toBeGreaterThan(0)
    const mlkem = crypto.find((c) => c.name === 'ML-KEM-1024')!
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
    const p384 = cryptoComponents(cdx).find((c) => c.name === 'P-384')!
    expect(p384.cryptoProperties.algorithmProperties.primitive).toBe('keyagree')
    expect(p384.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel).toBe(0)
    expect(cdx.metadata.properties.some((p) => p.value.includes('P-384'))).toBe(true)
  })

  it('emits the @noble dependency graph with pinned versions (TNO p.35)', () => {
    const cdx = toCycloneDx(buildCbom())
    const libs = libraryComponents(cdx)
    const pq = libs.find((l) => l.name === '@noble/post-quantum')!
    expect(pq.version).toBe('0.6.1')
    expect(pq.purl).toBe('pkg:npm/@noble/post-quantum@0.6.1')
    // dependency edges: app -> crypto assets; ML-DSA-87 -> its @noble library
    const appDep = cdx.dependencies.find((d) => d.ref === 'nerion')!
    expect(appDep.dependsOn).toContain('crypto/ML-DSA-87')
    const mldsaDep = cdx.dependencies.find((d) => d.ref === 'crypto/ML-DSA-87')!
    expect(mldsaDep.dependsOn).toContain('lib/@noble/post-quantum')
  })

  it('is deterministic', () => {
    expect(JSON.stringify(toCycloneDx(buildCbom(5)))).toBe(
      JSON.stringify(toCycloneDx(buildCbom(5))),
    )
  })
})
