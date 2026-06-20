// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * NSA CNSA 2.0 conformance oracle — machine-checkable classification of a PolarSeek
 * SuiteID against the Commercial National Security Algorithm Suite 2.0.
 *
 * Approved set (NSA CNSA 2.0, fact-checked June 2026 against the NSA CSA):
 *  - PQ signature:  ML-DSA-87 (FIPS 204, Category 5 ONLY — ML-DSA-44/65 not permitted)
 *  - PQ KEM:        ML-KEM-1024 (FIPS 203, Category 5 ONLY — ML-KEM-512/768 not permitted)
 *  - Symmetric:     AES-256 (FIPS 197)
 *  - General hash:  SHA-384 or SHA-512 (FIPS 180-4); SHA3/SHAKE is FIPS 202 but is approved
 *                   only for internal hardware-integrity functions, not general-purpose use.
 *  - Code/firmware signing: LMS or single-tree XMSS (NIST SP 800-208), or ML-DSA-87.
 *  - EXCLUDED from CNSA 2.0: SLH-DSA / SPHINCS+ (FIPS 205), Falcon / FN-DSA, HQC, ML-KEM-768.
 * Timeline: NSS support+prefer 2025; software/firmware exclusive-use 2030; and from
 * Jan 1 2027 all new NSS acquisitions must support CNSA 2.0.
 *
 * SCOPE (honest): this asserts ALGORITHM-SUITE conformance only — NOT FIPS 140-3 module
 * validation (requires a CMVP lab), NOT full CNSA 2.0 compliance (key management, LMS/XMSS
 * code-signing, protocol profiles). It is the verifiable algorithm-selection evidence a
 * reviewer wants, with the residual non-code gaps named explicitly.
 */

import type { Suite } from './types.js'

export type CnsaStatus = 'conformant' | 'transitional' | 'non-conformant'

export interface CnsaFinding {
  readonly component: 'signature' | 'kem' | 'symmetric' | 'mac' | 'hash'
  readonly algorithm: string
  readonly status: CnsaStatus
  readonly note: string
}

export interface CnsaAssessment {
  readonly suiteId: string
  /** No component is non-conformant (transitional hybrids/advisories are tolerated). */
  readonly conformant: boolean
  /** Every component is conformant — pure CNSA 2.0, no classical hybrid or SHA3 advisory. */
  readonly pureCnsa: boolean
  readonly findings: readonly CnsaFinding[]
}

const has = (s: string, sub: string): boolean => s.toUpperCase().includes(sub.toUpperCase())

function classifySignature(sigId: string): CnsaFinding {
  const c = (status: CnsaStatus, note: string): CnsaFinding => ({
    component: 'signature',
    algorithm: sigId,
    status,
    note,
  })
  if (has(sigId, 'ML-DSA-87'))
    return c('conformant', 'ML-DSA-87 (FIPS 204, Cat-5) — CNSA 2.0 signature.')
  if (has(sigId, 'SLH-DSA') || has(sigId, 'SPHINCS'))
    return c('non-conformant', 'SLH-DSA / SPHINCS+ (FIPS 205) is EXCLUDED from CNSA 2.0.')
  if (has(sigId, 'FN-DSA') || has(sigId, 'FALCON'))
    return c('non-conformant', 'Falcon / FN-DSA is not a CNSA 2.0 algorithm.')
  // Multi-tree HBS first (XMSSMT contains "XMSS"): CNSA 2.0 excludes HSS/XMSS^MT.
  if (has(sigId, 'HSS') || has(sigId, 'XMSSMT') || has(sigId, '_MT_') || has(sigId, 'MT-'))
    return c(
      'non-conformant',
      'HSS / XMSS^MT multi-tree is EXCLUDED by CNSA 2.0; single-tree only.',
    )
  if (has(sigId, 'LMS') || has(sigId, 'XMSS'))
    return c('conformant', 'single-tree LMS/XMSS (SP 800-208) — CNSA 2.0 code/firmware signing.')
  return c(
    'non-conformant',
    'Not a CNSA 2.0 signature (CNSA 2.0 = ML-DSA-87, or LMS/XMSS for code signing).',
  )
}

function classifyKem(kemId: string): CnsaFinding {
  const c = (status: CnsaStatus, note: string): CnsaFinding => ({
    component: 'kem',
    algorithm: kemId,
    status,
    note,
  })
  const ml1024 = has(kemId, 'MLKEM1024') || has(kemId, 'ML-KEM-1024')
  const classical =
    has(kemId, 'P384') || has(kemId, 'P-384') || has(kemId, 'X25519') || has(kemId, 'X448')
  if (ml1024 && classical)
    return c(
      'transitional',
      'ML-KEM-1024 (CNSA 2.0) in a classical hybrid; the CNSA 2.0 target is pure ML-KEM-1024.',
    )
  if (ml1024) return c('conformant', 'ML-KEM-1024 (FIPS 203, Cat-5) — CNSA 2.0 KEM.')
  if (has(kemId, 'MLKEM768') || has(kemId, 'ML-KEM-768'))
    return c('non-conformant', 'ML-KEM-768 is not approved; CNSA 2.0 requires ML-KEM-1024.')
  if (has(kemId, 'HQC')) return c('non-conformant', 'HQC is not a CNSA 2.0 algorithm.')
  return c('non-conformant', 'Not a CNSA 2.0 KEM (CNSA 2.0 = ML-KEM-1024).')
}

function classifySymmetric(aeadId: string): CnsaFinding {
  if (has(aeadId, 'AES-256') || has(aeadId, 'AES256'))
    return {
      component: 'symmetric',
      algorithm: aeadId,
      status: 'conformant',
      note: 'AES-256 (FIPS 197) — CNSA 2.0 symmetric.',
    }
  return {
    component: 'symmetric',
    algorithm: aeadId,
    status: 'non-conformant',
    note: 'CNSA 2.0 requires AES-256.',
  }
}

function classifyHashLike(id: string, component: 'mac' | 'hash'): CnsaFinding {
  const c = (status: CnsaStatus, note: string): CnsaFinding => ({
    component,
    algorithm: id,
    status,
    note,
  })
  if (has(id, 'SHA-384') || has(id, 'SHA384') || has(id, 'SHA-512') || has(id, 'SHA512'))
    return c('conformant', 'SHA-384/512 (FIPS 180-4) — CNSA 2.0 hash.')
  if (has(id, 'SHA3') || has(id, 'SHAKE'))
    return c(
      'transitional',
      'SHA3/SHAKE is FIPS 202 but CNSA 2.0 general-purpose hashing is SHA-384/512 (SHA3 only for internal hardware integrity).',
    )
  return c('non-conformant', 'Not a CNSA 2.0 hash (CNSA 2.0 general hashing = SHA-384/512).')
}

/** Classify a suite's algorithm selection against CNSA 2.0. */
export function assessCnsa20(suite: Suite): CnsaAssessment {
  const findings: CnsaFinding[] = [
    classifySignature(suite.sigId),
    classifyKem(suite.kemId),
    classifySymmetric(suite.aeadId),
    classifyHashLike(suite.macId, 'mac'),
    classifyHashLike(suite.hashId, 'hash'),
  ]
  return {
    suiteId: suite.id,
    conformant: findings.every((f) => f.status !== 'non-conformant'),
    pureCnsa: findings.every((f) => f.status === 'conformant'),
    findings,
  }
}
