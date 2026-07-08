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
import { NERION_DEPENDENCIES } from './supplychain.js'

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

export interface CycloneDxLibraryComponent {
  readonly type: 'library'
  readonly name: string
  readonly version: string
  readonly 'bom-ref': string
  readonly purl: string
}

export interface CycloneDxDependency {
  readonly ref: string
  readonly dependsOn: readonly string[]
}

export interface CycloneDxBom {
  readonly bomFormat: 'CycloneDX'
  readonly specVersion: '1.6'
  readonly metadata: {
    readonly timestamp: number
    readonly component: {
      readonly type: 'application'
      readonly name: string
      readonly 'bom-ref': string
    }
    readonly properties: readonly CycloneDxProperty[]
  }
  readonly components: readonly (CycloneDxComponent | CycloneDxLibraryComponent)[]
  readonly dependencies: readonly CycloneDxDependency[]
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

const APP_REF = 'nerion'

/** Map a crypto asset to the @noble library that implements it (TNO Handbook p.35 graph). */
function assetLibrary(asset: CryptoAsset): string | undefined {
  const n = asset.name.toUpperCase()
  if (/ML-KEM|ML-DSA|SLH-DSA|HQC|FN-DSA|FALCON/.test(n)) return '@noble/post-quantum'
  if (n.includes('P-384') || n.includes('X25519')) return '@noble/curves'
  if (n.includes('AES')) return '@noble/ciphers'
  if (n.includes('SHA')) return '@noble/hashes'
  return undefined
}

/**
 * Project a native Nerion CBOM onto CycloneDX 1.6, including the
 * application -> algorithm -> @noble-library DEPENDENCY GRAPH with pinned library
 * versions (TNO PQC Migration Handbook p.35). The native signed CBOM stays the
 * source of truth; this is an additive interop rendering. Deterministic: the input
 * CBOM's sorted asset order is preserved and libraries are emitted sorted.
 */
export function toCycloneDx(cbom: Cbom): CycloneDxBom {
  const cryptoComponents = cbom.assets.map(toComponent)
  const versionOf = new Map(NERION_DEPENDENCIES.map((d) => [d.name, d.version] as [string, string]))

  const assetToLib = new Map<string, string>()
  const usedLibs = new Set<string>()
  for (const asset of cbom.assets) {
    const lib = assetLibrary(asset)
    if (lib !== undefined) {
      assetToLib.set(asset.name, lib)
      usedLibs.add(lib)
    }
  }
  const libComponents: CycloneDxLibraryComponent[] = [...usedLibs].sort().map((name) => {
    const version = versionOf.get(name) ?? 'unknown'
    return {
      type: 'library' as const,
      name,
      version,
      'bom-ref': `lib/${name}`,
      purl: `pkg:npm/${name}@${version}`,
    }
  })

  const dependencies: CycloneDxDependency[] = [
    { ref: APP_REF, dependsOn: cryptoComponents.map((c) => c['bom-ref']) },
    ...cbom.assets.map((a) => {
      const lib = assetToLib.get(a.name)
      return { ref: `crypto/${a.name}`, dependsOn: lib !== undefined ? [`lib/${lib}`] : [] }
    }),
  ]

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    metadata: {
      timestamp: cbom.generatedAt,
      component: { type: 'application', name: 'Nerion', 'bom-ref': APP_REF },
      properties: [
        { name: 'nerion:source', value: cbom.bomFormat },
        { name: 'nerion:quantumVulnerable', value: cbom.quantumVulnerable.join(',') },
      ],
    },
    components: [...cryptoComponents, ...libComponents],
    dependencies,
  }
}
