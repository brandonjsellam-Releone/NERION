// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * CycloneDX 1.6 `cryptoProperties` projection of the native signed CBOM.
 *
 * The TNO PQC Migration Handbook (2nd ed., p.34-35, p.114) names CycloneDX as the
 * canonical cryptographic-bill-of-materials format. Nerion's native CBOM
 * (`cbom.ts`) stays the source of truth — it is deterministically registry-derived,
 * ML-DSA-87-signed, and transparency-log-anchored. This module is an additive
 * INTEROP rendering onto the OWASP CycloneDX schema, NOT a second inventory and
 * NOT signed; consumers that want integrity verify the native signed CBOM.
 */

import type { Cbom, CryptoAsset } from './cbom.js'

/** Nerion primitive -> CycloneDX 1.6 `algorithmProperties.primitive` enum. */
const PRIMITIVE_MAP: Record<CryptoAsset['primitive'], string> = {
  kem: 'kem',
  kex: 'keyagree',
  signature: 'signature',
  ae: 'ae',
  mac: 'mac',
  hash: 'hash',
}

/** Nerion primitive -> CycloneDX 1.6 `cryptoFunctions` enum values. */
const FUNCTIONS_MAP: Record<CryptoAsset['primitive'], readonly string[]> = {
  kem: ['encapsulate', 'decapsulate'],
  kex: ['keygen', 'keyderive'],
  signature: ['keygen', 'sign', 'verify'],
  ae: ['encrypt', 'decrypt', 'tag'],
  mac: ['tag', 'verify'],
  hash: ['digest'],
}

export interface CycloneDxProperty {
  readonly name: string
  readonly value: string
}

export interface CycloneDxAlgorithmProperties {
  readonly primitive: string
  readonly parameterSetIdentifier: string
  readonly executionEnvironment: 'software-plain-ram'
  readonly cryptoFunctions: readonly string[]
  /** 0 = none/classical; 1-5 = NIST PQC category. */
  readonly nistQuantumSecurityLevel: number
}

export interface CycloneDxComponent {
  readonly type: 'cryptographic-asset'
  readonly name: string
  readonly 'bom-ref': string
  readonly cryptoProperties: {
    readonly assetType: 'algorithm'
    readonly algorithmProperties: CycloneDxAlgorithmProperties
  }
  readonly properties: readonly CycloneDxProperty[]
}

export interface CycloneDxBom {
  readonly bomFormat: 'CycloneDX'
  readonly specVersion: '1.6'
  readonly metadata: {
    readonly timestamp: number
    readonly component: { readonly type: 'application'; readonly name: string }
    readonly properties: readonly CycloneDxProperty[]
  }
  readonly components: readonly CycloneDxComponent[]
}

function toComponent(asset: CryptoAsset): CycloneDxComponent {
  const properties: CycloneDxProperty[] = [
    { name: 'nerion:nistStandard', value: asset.nistStandard },
    { name: 'nerion:quantumClass', value: asset.quantum },
    { name: 'nerion:status', value: asset.status },
    { name: 'nerion:deprecation', value: asset.deprecation },
  ]
  for (const [k, v] of Object.entries(asset.sizesBytes)) {
    properties.push({ name: `nerion:size:${k}Bytes`, value: String(v) })
  }
  return {
    type: 'cryptographic-asset',
    name: asset.name,
    'bom-ref': `crypto/${asset.name}`,
    cryptoProperties: {
      assetType: 'algorithm',
      algorithmProperties: {
        primitive: PRIMITIVE_MAP[asset.primitive],
        parameterSetIdentifier: asset.parameterSet,
        executionEnvironment: 'software-plain-ram',
        cryptoFunctions: FUNCTIONS_MAP[asset.primitive],
        nistQuantumSecurityLevel: asset.nistLevel,
      },
    },
    properties,
  }
}

/**
 * Project a native Nerion CBOM onto CycloneDX 1.6. Deterministic: the input CBOM's
 * asset order (sorted) is preserved, so two projections of the same CBOM are
 * byte-identical.
 */
export function toCycloneDx(cbom: Cbom): CycloneDxBom {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    metadata: {
      timestamp: cbom.generatedAt,
      component: { type: 'application', name: 'Nerion' },
      properties: [
        { name: 'nerion:source', value: cbom.bomFormat },
        { name: 'nerion:quantumVulnerable', value: cbom.quantumVulnerable.join(',') },
      ],
    },
    components: cbom.assets.map(toComponent),
  }
}
