// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Cryptographic Bill of Materials (CBOM) — a machine-readable cryptographic
 * inventory that SUPPORTS the NSM-10 / OMB M-23-02 requirement for agencies to
 * inventory quantum-vulnerable cryptography. (Honest: NSM-10/OMB mandate the
 * inventory, not a specific format; a CBOM is a tool to help satisfy it.) Classical
 * public-key algorithms are slated for deprecation ~2030 / disallowance ~2035 under
 * NSA CNSA 2.0 and the NIST PQC transition (IR 8547 ipd) — the assets to flag.
 *
 * Emitted deterministically from the SuiteID registry: every algorithm in the
 * active suites (hybrid KEMs decomposed into their legs) with its primitive, NIST
 * standard, quantum-resistance class, CNSA 2.0 status, and deprecation note. The
 * CBOM is then ML-DSA-87-signed and transparency-log-anchored (reusing the signed-
 * envelope machinery), so a reviewer gets a verifiable inventory, not a spreadsheet.
 *
 * The headline a migration reviewer wants: the QUANTUM-VULNERABLE assets (the
 * classical hybrid legs — P-384, X25519 — broken by Shor) are flagged explicitly;
 * the PQ legs (ML-KEM/ML-DSA) and the 256-bit symmetric/hash primitives (Grover-
 * resistant) are not. Honest scope (ADR-0008/0009): algorithm inventory only — not
 * FIPS 140-3 module validation, not a full system SBOM.
 */

import {
  allSuites,
  encodeCanonical,
  signEnvelope,
  verifyEnvelope,
  type Bytes,
  type SignedEnvelope,
} from '../../crypto/src/index.js'
import { assertCnsa } from './cnsa-oracle.js'

const CBOM_CONTEXT = 'PolarSeek-CBOM-v1'

export type QuantumClass =
  | 'pq-cat5'
  | 'pq-cat3'
  | 'pq-other'
  | 'quantum-resistant-symmetric'
  | 'quantum-vulnerable'

export interface CryptoAsset {
  readonly name: string
  readonly primitive: 'kem' | 'kex' | 'signature' | 'ae' | 'mac' | 'hash'
  readonly parameterSet: string
  readonly nistStandard: string
  readonly quantum: QuantumClass
  readonly deprecation: string
}

export interface CbomSuiteEntry {
  readonly suiteId: string
  readonly status: string
  readonly cnsaLevel: string
  readonly assets: readonly string[]
}

export interface Cbom {
  readonly bomFormat: 'PolarSeek-CBOM'
  readonly specVersion: '1.0'
  readonly generatedAt: number
  readonly subject: string
  readonly suites: readonly CbomSuiteEntry[]
  readonly assets: readonly CryptoAsset[]
  /** Names of the quantum-vulnerable (Shor-broken) assets — the migration headline. */
  readonly quantumVulnerable: readonly string[]
}

const has = (s: string, sub: string): boolean => s.toUpperCase().includes(sub.toUpperCase())

/** Decompose a (possibly hybrid) KEM id into its component algorithm legs. */
function kemLegs(kemId: string): string[] {
  if (has(kemId, 'XWING')) return ['ML-KEM-768', 'X25519']
  if (has(kemId, 'MLKEM1024') || has(kemId, 'ML-KEM-1024')) {
    return has(kemId, 'P384') || has(kemId, 'P-384') ? ['ML-KEM-1024', 'P-384'] : ['ML-KEM-1024']
  }
  if (has(kemId, 'HQC')) return ['HQC-256']
  return [kemId]
}

/** Classify a single algorithm leg into a CBOM asset. */
function classify(id: string): CryptoAsset {
  const a = (
    primitive: CryptoAsset['primitive'],
    parameterSet: string,
    nistStandard: string,
    quantum: QuantumClass,
    deprecation: string,
  ): CryptoAsset => ({ name: id, primitive, parameterSet, nistStandard, quantum, deprecation })

  if (has(id, 'ML-DSA-87'))
    return a('signature', 'ML-DSA-87', 'FIPS 204', 'pq-cat5', 'current (CNSA 2.0).')
  if (has(id, 'SLH-DSA') || has(id, 'SPHINCS'))
    return a(
      'signature',
      'SLH-DSA-SHAKE-256f',
      'FIPS 205',
      'pq-cat5',
      'current (FIPS 205; EXCLUDED from CNSA 2.0).',
    )
  if (has(id, 'FN-DSA') || has(id, 'FALCON'))
    return a('signature', 'FN-DSA-1024', 'FIPS 206 (draft)', 'pq-cat5', 'pending standardization.')
  if (has(id, 'ML-KEM-1024') || has(id, 'MLKEM1024'))
    return a('kem', 'ML-KEM-1024', 'FIPS 203', 'pq-cat5', 'current (CNSA 2.0).')
  if (has(id, 'ML-KEM-768') || has(id, 'MLKEM768'))
    return a('kem', 'ML-KEM-768', 'FIPS 203', 'pq-cat3', 'current (Cat-3; below CNSA 2.0 Cat-5).')
  if (has(id, 'HQC'))
    return a('kem', 'HQC-256', 'FIPS 207 (draft)', 'pq-other', 'pending standardization.')
  if (has(id, 'P-384') || has(id, 'P384'))
    return a(
      'kex',
      'ECDH P-384',
      'SP 800-186',
      'quantum-vulnerable',
      'Shor-broken; deprecate ~2030 / disallow ~2035 (NSA CNSA 2.0 + NIST PQC transition).',
    )
  if (has(id, 'X25519'))
    return a(
      'kex',
      'X25519',
      'SP 800-186 / RFC 7748',
      'quantum-vulnerable',
      'Shor-broken; deprecate ~2030 / disallow ~2035 (NSA CNSA 2.0 + NIST PQC transition).',
    )
  if (has(id, 'AES-256') || has(id, 'AES256'))
    return a(
      'ae',
      'AES-256-GCM',
      'FIPS 197 / SP 800-38D',
      'quantum-resistant-symmetric',
      'current (CNSA 2.0; 256-bit is Grover-resistant).',
    )
  if (has(id, 'SHA-384') || has(id, 'SHA384'))
    return a(
      'mac',
      'HMAC-SHA-384',
      'FIPS 198-1 / 180-4',
      'quantum-resistant-symmetric',
      'current (CNSA 2.0).',
    )
  if (has(id, 'SHA3') || has(id, 'SHAKE'))
    return a(
      'hash',
      'SHA3-256 / SHAKE256',
      'FIPS 202',
      'quantum-resistant-symmetric',
      'current (FIPS 202; CNSA 2.0 prefers SHA-2 for general hashing).',
    )
  return a('hash', id, 'unknown', 'quantum-resistant-symmetric', 'unclassified algorithm id.')
}

/** Build a deterministic CBOM over the active SuiteID registry. */
export function buildCbom(now = 0): Cbom {
  const active = allSuites()
    .filter((s) => s.status === 'active')
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))

  const byName = new Map<string, CryptoAsset>()
  const suites: CbomSuiteEntry[] = active.map((s) => {
    const ids = [...kemLegs(s.kemId), s.sigId, s.aeadId, s.macId, s.hashId]
    const names: string[] = []
    for (const id of ids) {
      const asset = classify(id)
      if (!byName.has(asset.name)) byName.set(asset.name, asset)
      if (!names.includes(asset.name)) names.push(asset.name)
    }
    return {
      suiteId: s.id,
      status: s.status,
      cnsaLevel: assertCnsa(s).level,
      assets: names.sort(),
    }
  })

  const assets = [...byName.values()].sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  )
  const quantumVulnerable = assets
    .filter((a) => a.quantum === 'quantum-vulnerable')
    .map((a) => a.name)

  return {
    bomFormat: 'PolarSeek-CBOM',
    specVersion: '1.0',
    generatedAt: now,
    subject: 'PolarSeek active cryptographic suites',
    suites,
    assets,
    quantumVulnerable,
  }
}

/** Deterministically ML-DSA-87-sign a CBOM into a domain-separated envelope. */
export function signCbom(cbom: Cbom, suite: string, issuerSecretKey: Bytes): SignedEnvelope {
  return signEnvelope(cbom, suite, issuerSecretKey, CBOM_CONTEXT)
}

/** Verify a signed CBOM under the expected issuer key (+ optional suite allow-list). */
export function verifyCbom(
  env: SignedEnvelope,
  issuerPublicKey: Bytes,
  allowedSuites?: readonly string[],
): boolean {
  return env.context === CBOM_CONTEXT && verifyEnvelope(env, issuerPublicKey, allowedSuites)
}

/** Canonical bytes to anchor a signed CBOM as a transparency-log leaf. */
export function cbomLeaf(env: SignedEnvelope): Bytes {
  return encodeCanonical(env)
}
