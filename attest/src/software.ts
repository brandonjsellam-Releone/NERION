// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Software attester + the generic verifier (appraisal).
 *
 * SoftwareAttester signs a session statement with an attestation root key
 * (ML-DSA via the suite). `appraise` verifies the signature, trusted-attester
 * membership, nonce freshness, and expiry. Hardware TEE formats are rejected
 * with a CONNECT pointer until a real quote-verification adapter exists.
 */

import {
  DOMAIN_TAGS,
  encodeCanonical,
  signerFor,
  getSuite,
  constantTimeEqual,
  type Bytes,
  type KeyPair,
} from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { AppraisalPolicy, AppraisalResult, AttestationClaims, Evidence } from './types.js'
import type { QuoteVerifierRegistry } from './verifiers.js'

const HARDWARE_FORMATS = new Set(['tdx', 'sev-snp', 'cca', 'tpm'])
/** Decode-side cap on an n-of-m evidence array before per-item ML-DSA-87 verification (AAC cycle-4). */
const MAX_EVIDENCES = 256

// Domain-separated signing message that BINDS the suite into the evidence signature
// (algorithm-downgrade / cross-suite confusion — ATTEST-SUITE-001, Team Apex 2026-06-21) and
// separates attestation signatures from any other ML-DSA use of the attester key. Changing the
// unsigned envelope `suite` now breaks verification rather than silently re-routing the verifier.
const ATTEST_CONTEXT = DOMAIN_TAGS.ATTEST_EVIDENCE
function attestSigningMessage(suite: string, claims: AttestationClaims): Bytes {
  return encodeCanonical([ATTEST_CONTEXT, suite, claims])
}

export class SoftwareAttester {
  constructor(
    private readonly suite: string,
    private readonly key: KeyPair,
  ) {}

  get publicKey(): Bytes {
    return this.key.publicKey
  }

  /** Produce signed evidence binding a session identity key + nonce. */
  produce(sessionId: string, sessionPublicKey: string, nonce: string, notAfter: number): Evidence {
    const claims: AttestationClaims = {
      format: 'software-dev',
      sessionId,
      sessionPublicKey,
      nonce,
      notAfter,
    }
    const sig = signerFor(this.suite).sign(
      attestSigningMessage(this.suite, claims),
      this.key.secretKey,
    )
    return {
      claims,
      format: 'software-dev',
      attesterPublicKey: this.key.publicKey,
      sig,
      suite: this.suite,
    }
  }
}

/**
 * Appraise a single piece of evidence against a policy. For hardware (TEE)
 * formats, a registered quote verifier is consulted; with none registered the
 * format is rejected with a CONNECT pointer.
 */
export function appraise(
  evidence: Evidence,
  policy: AppraisalPolicy,
  verifiers?: QuoteVerifierRegistry,
): AppraisalResult {
  const reasons: string[] = []

  // ATTEST-SHAPE-001 (AAC cycle-4): `evidence` and its sub-fields are attacker-controlled wire values
  // (TS types them, but a wire decoder can hand us anything). Guard their runtime shape BEFORE any
  // dereference below — `evidence.claims.format` (:89) and `constantTimeEqual(k, evidence.attesterPublicKey)`
  // (:109) otherwise throw a TypeError on null/missing fields that ESCAPES appraise(), aborting an
  // entire appraiseNofM() quorum from a single hostile item and crashing establishSession(). The
  // ATTEST-SUITE-THROW fix only wrapped the signer; these two earlier derefs were unguarded. Fail closed.
  const ev = evidence as unknown as {
    claims?: unknown
    attesterPublicKey?: unknown
    suite?: unknown
  }
  if (
    ev == null ||
    ev.claims == null ||
    typeof ev.claims !== 'object' ||
    !(ev.attesterPublicKey instanceof Uint8Array) ||
    typeof ev.suite !== 'string'
  ) {
    return {
      valid: false,
      reasons: ['evidence is malformed (missing/invalid claims, attester key, or suite)'],
      claims: null,
    }
  }

  // The signature binds ONLY evidence.claims (see produce()/the verify below);
  // the top-level evidence.format is an UNSIGNED wire field. Gating policy
  // acceptance or TEE-quote routing on it let an attacker relabel a genuine,
  // signed hardware quote (claims.format='tdx') as 'software-dev' to skip the
  // quote/measurement verifier entirely while still returning claims.format='tdx'
  // downstream. Bind to the SIGNED format and reject any envelope/claims
  // disagreement (ATTEST-FMT-001, Team Apex 2026-06-21).
  const format = evidence.claims.format
  if (evidence.format !== format) {
    reasons.push('format mismatch between unsigned envelope and signed claims')
  }

  if (!policy.acceptedFormats.includes(format)) {
    reasons.push(`format "${format}" not accepted by policy`)
  }
  if (HARDWARE_FORMATS.has(format)) {
    const verifier = verifiers?.get(format)
    if (!verifier) {
      reasons.push(
        `TEE quote verification for "${format}" is not implemented ` +
          `(CONNECT: ${format} attestation verification SDK)`,
      )
    } else {
      const verdict = verifier.verify(evidence, policy.expectedMeasurements ?? [])
      if (!verdict.ok) reasons.push(...verdict.reasons)
    }
  }
  if (!policy.trustedAttesters.some((k) => constantTimeEqual(k, evidence.attesterPublicKey))) {
    reasons.push('attester key is not in the trusted set')
  }
  // F10 (Team Apex max sweep 2026-06-28): silent suite/category DOWNGRADE. evidence.suite is
  // signed-bound (ATTEST-SUITE-001, no relabeling) but was otherwise unconstrained, and
  // signerFor() verifies every suite with the same ML-DSA-87 key — so a genuinely-keyed weaker
  // suite (PS-1, Cat-3) was accepted where Cat-5 was required. Let the appraiser pin an explicit
  // suite allowlist and/or a minimum CNSA category; both fail closed (unknown suite ⇒ category -1).
  if (policy.acceptedSuites !== undefined && !policy.acceptedSuites.includes(evidence.suite)) {
    reasons.push(`suite "${evidence.suite}" is not in the policy's accepted suites`)
  }
  if (policy.minCategory !== undefined) {
    let category = -1
    try {
      category = getSuite(evidence.suite).category
    } catch {
      category = -1 // unknown / unresolvable suite — fail closed
    }
    if (category < policy.minCategory) {
      reasons.push(
        `suite "${evidence.suite}" category ${category} is below the required minimum ${policy.minCategory}`,
      )
    }
  }
  // ATTEST-SUITE-THROW (Team Apex sweep): `evidence.suite` is an attacker-controlled wire field, and
  // signerFor() THROWS UnknownSuiteError on a bogus suite — which would crash appraise()/appraiseNofM()
  // (one hostile evidence aborting the whole n-of-m quorum) and establishSession, instead of returning
  // invalid. Resolve the signer defensively and fail closed on any throw, mirroring ledger's safeVerify
  // (LEDGER-003/004). The suite is bound into the signed message (ATTEST-SUITE-001), so a bogus suite
  // can never yield a VALID result — this only converts the crash into a clean rejection.
  let sigValid = false
  try {
    sigValid = signerFor(evidence.suite).verify(
      evidence.sig,
      attestSigningMessage(evidence.suite, evidence.claims),
      evidence.attesterPublicKey,
    )
  } catch {
    sigValid = false
  }
  if (!sigValid) {
    reasons.push('evidence signature is invalid (or unresolvable suite)')
  }
  if (evidence.claims.nonce !== policy.expectedNonce) {
    reasons.push('nonce mismatch (stale or replayed attestation)')
  }
  // Fail-closed on a non-safe-integer clock / expiry: a NaN `policy.now` OR a signed
  // `notAfter` that is non-finite, fractional, or > 2^53 makes `now > notAfter` false and
  // would SILENTLY skip the expiry check (ATTEST-TIME-001/ATTEST-EXP-001, same class as the
  // fixed KERNEL-TIME-001). F9 (Team Apex max sweep 2026-06-28): the clock used
  // Number.isSafeInteger but notAfter only used Number.isFinite — so a *signed* notAfter of
  // 1e30 (finite, not a safe integer) passed and `now > 1e30` was always false, yielding an
  // attestation that never expires (defeating re-attestation / revocation). A unix-seconds
  // timestamp is always a safe integer; require BOTH sides to be safe integers, matching the
  // sibling guards in grant.ts / quorum.ts and the permit-exp clamp in planes/node.ts.
  if (!Number.isSafeInteger(policy.now) || !Number.isSafeInteger(evidence.claims.notAfter)) {
    reasons.push('attestation expiry uncheckable (non-safe-integer clock or notAfter)')
  } else if (policy.now > evidence.claims.notAfter) {
    reasons.push('attestation has expired')
  }

  return reasons.length === 0
    ? { valid: true, reasons, claims: evidence.claims }
    : { valid: false, reasons, claims: null }
}

/**
 * N-of-M heterogeneous appraisal for high tiers: valid iff the valid evidences cover
 * at least `n` DISTINCT formats AND at least `n` DISTINCT attester keys (independent
 * roots of trust). Counting formats alone let a single trusted attester satisfy the
 * quorum across relabeled formats (ATTEST-NOFM-001, Team Apex 2026-06-21).
 */
export function appraiseNofM(
  evidences: readonly Evidence[],
  policy: AppraisalPolicy,
  n: number,
  verifiers?: QuoteVerifierRegistry,
): AppraisalResult {
  // A non-positive / non-integer threshold would make the size checks below trivially true
  // (size >= 0) and index an empty `valid` array — fail closed (ATTEST-NOFM-002, Team Apex).
  if (!Number.isSafeInteger(n) || n < 1) {
    return { valid: false, reasons: ['n-of-m threshold must be a positive integer'], claims: null }
  }
  // Decode-side DoS cap (AAC cycle-4): each evidence costs an ML-DSA-87 verify in appraise(); bound the
  // attacker-supplied array before iterating (at most a few distinct roots of trust are ever needed).
  if (evidences.length > MAX_EVIDENCES) {
    return {
      valid: false,
      reasons: [`evidence count ${evidences.length} exceeds bound ${MAX_EVIDENCES}`],
      claims: null,
    }
  }
  const valid = evidences
    .map((e) => ({ e, r: appraise(e, policy, verifiers) }))
    .filter((x) => x.r.valid)
  const formats = new Set(valid.map((x) => x.r.claims!.format))
  const attesters = new Set(valid.map((x) => bytesToHex(x.e.attesterPublicKey)))
  // ATTEST-NOFM-003 (Team Apex sweep): all n independent attestations must corroborate the SAME
  // session. Without this, n distinct roots each vouching for a DIFFERENT sessionPublicKey form a
  // valid n-of-m quorum that certifies whichever session is first (valid[0]) — cross-session
  // corroboration forgery. Pin the quorum to a single session identity.
  const sessions = new Set(valid.map((x) => x.r.claims!.sessionPublicKey))
  if (sessions.size > 1) {
    return {
      valid: false,
      reasons: ['n-of-m attestations corroborate different sessions (must agree on one)'],
      claims: null,
    }
  }
  if (formats.size >= n && attesters.size >= n) {
    return { valid: true, reasons: [], claims: valid[0]!.r.claims }
  }
  return {
    valid: false,
    reasons: [
      `require ${n} heterogeneous valid attestations from distinct attesters, got ` +
        `${formats.size} format(s) / ${attesters.size} attester(s)`,
    ],
    claims: null,
  }
}
