// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Signed, transparency-anchorable CNSA 2.0 conformance verdict.
 *
 * Wraps the pure `assessCnsa20` classifier (crypto/src/cnsa.ts) into a GOV-GRADE
 * ARTIFACT: a deterministic, ML-DSA-87-signed, externally-verifiable statement of
 * a suite's NSA CNSA 2.0 conformance that can be anchored in the transparency log.
 * A National Security Systems reviewer gets a checkable verdict, not an assertion.
 *
 * Deny-by-default framing: any component outside the CNSA 2.0 allow-set produces a
 * finding. HARD findings (non-conformant signature / KEM / symmetric / MAC) fail
 * conformance; WARN findings (SHA3/SHAKE general hashing, or an ML-KEM-1024
 * classical hybrid) are advisory and yield the 'transitional' level. Honest scope
 * (ADR-0008): algorithm-suite conformance only — NOT FIPS 140-3 module validation.
 */

import {
  assessCnsa20,
  DOMAIN_TAGS,
  getSuite,
  encodeCanonical,
  signEnvelope,
  verifyEnvelope,
  type Suite,
  type SuiteId,
  type Bytes,
  type SignedEnvelope,
} from '../../crypto/src/index.js'

const CNSA_VERDICT_CONTEXT = DOMAIN_TAGS.CNSA_VERDICT

export type CnsaLevel = 'CNSA-2.0-Cat5-pure' | 'CNSA-2.0-Cat5-transitional' | 'non-conformant'

export interface CnsaVerdictFinding {
  readonly fieldPath: 'sigId' | 'kemId' | 'aeadId' | 'macId' | 'hashId'
  readonly value: string
  readonly severity: 'HARD' | 'WARN'
  readonly reason: string
}

export interface CnsaVerdict {
  readonly target: string
  readonly suiteId: string
  readonly conformant: boolean
  readonly level: CnsaLevel
  readonly findings: readonly CnsaVerdictFinding[]
  /** Caller-supplied issuance time (the codebase reads no ambient clock). */
  readonly ts: number
}

const COMPONENT_FIELD = {
  signature: 'sigId',
  kem: 'kemId',
  symmetric: 'aeadId',
  mac: 'macId',
  hash: 'hashId',
} as const

/**
 * Produce a deterministic CNSA 2.0 conformance verdict for a suite (id or object).
 * conformant iff no HARD finding; level is pure (no findings), transitional (WARN
 * only), or non-conformant (any HARD).
 */
export function assertCnsa(target: SuiteId | Suite, now = 0): CnsaVerdict {
  const suite: Suite = typeof target === 'string' ? getSuite(target) : target
  const findings: CnsaVerdictFinding[] = assessCnsa20(suite)
    .findings.filter((f) => f.status !== 'conformant')
    .map((f) => ({
      fieldPath: COMPONENT_FIELD[f.component],
      value: f.algorithm,
      severity: f.status === 'non-conformant' ? ('HARD' as const) : ('WARN' as const),
      reason: f.note,
    }))
  const hard = findings.some((f) => f.severity === 'HARD')
  const warn = findings.some((f) => f.severity === 'WARN')
  const level: CnsaLevel = hard
    ? 'non-conformant'
    : warn
      ? 'CNSA-2.0-Cat5-transitional'
      : 'CNSA-2.0-Cat5-pure'
  return {
    target: typeof target === 'string' ? target : suite.id,
    suiteId: suite.id,
    conformant: !hard,
    level,
    findings,
    ts: now,
  }
}

/** Deterministically ML-DSA-87-sign a verdict into a domain-separated envelope. */
export function signCnsaVerdict(
  v: CnsaVerdict,
  suite: string,
  issuerSecretKey: Bytes,
): SignedEnvelope {
  return signEnvelope(v, suite, issuerSecretKey, CNSA_VERDICT_CONTEXT)
}

/** Verify a signed verdict under the expected issuer key (+ optional suite allow-list). */
export function verifyCnsaVerdict(
  env: SignedEnvelope,
  issuerPublicKey: Bytes,
  allowedSuites?: readonly string[],
): boolean {
  return env.context === CNSA_VERDICT_CONTEXT && verifyEnvelope(env, issuerPublicKey, allowedSuites)
}

/** Canonical bytes to anchor a signed verdict as a transparency-log leaf. */
export function cnsaVerdictLeaf(env: SignedEnvelope): Bytes {
  return encodeCanonical(env)
}
