// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * SuiteID registry & negotiation.
 *
 * A SuiteID names a complete, versioned cipher suite. Every signed/encrypted
 * PolarSeek object carries its SuiteID so peers can negotiate and so receipts
 * record exactly which algorithms produced them. No algorithm is ever
 * hard-coded into protocol logic — callers resolve primitives via the suite.
 *
 *   PS-1  general / CNSA-transition tier  (X-Wing KEM + ML-DSA-87)
 *   PS-5  regulated CNSA 2.0 Cat-5 tier   (ML-KEM-1024+P-384 KEM + ML-DSA-87)
 *
 * Pending/agility entries (HQC backup KEM, Falcon receipts) are registered with
 * non-active status so they appear in the catalog but are never negotiated.
 */

import type { Suite, Bytes } from './types.js'
import { UnknownSuiteError, NoCommonSuiteError } from './errors.js'
import { KEM_IDS, getKem } from './kem.js'
import { SIG_IDS, getSigner } from './sign.js'
import { encodeCanonical } from './cbor.js'
import { SHA3_SHAKE256, constantTimeEqual } from './symmetric.js'
import type { Kem, SignatureScheme } from './types.js'

export const SUITE_IDS = {
  PS_1: 'PS-1',
  PS_5: 'PS-5',
  /** Agility: PS-5 with HQC code-based backup KEM (pending FIPS 207). */
  PS_5_HQC: 'PS-5-HQC',
  /** Agility: compact receipts via Falcon/FN-DSA (pending FIPS 206). */
  PS_5_FN: 'PS-5-FN',
} as const

export type SuiteId = (typeof SUITE_IDS)[keyof typeof SUITE_IDS]

const SUITES: Record<string, Suite> = {
  [SUITE_IDS.PS_1]: {
    id: SUITE_IDS.PS_1,
    status: 'active',
    category: 3,
    preference: 20,
    kemId: KEM_IDS.XWING,
    sigId: SIG_IDS.ML_DSA_87,
    aeadId: 'AES-256-GCM',
    macId: 'HMAC-SHA-384',
    hashId: 'SHA3-256/SHAKE256',
    description: 'General tier: X-Wing (X25519+ML-KEM-768) KEM, ML-DSA-87 signatures.',
    standards: 'FIPS 203/204; IETF draft-connolly-cfrg-xwing-kem; CNSA 2.0 transition.',
  },
  [SUITE_IDS.PS_5]: {
    id: SUITE_IDS.PS_5,
    status: 'active',
    category: 5,
    preference: 10,
    kemId: KEM_IDS.MLKEM1024_P384,
    sigId: SIG_IDS.ML_DSA_87,
    aeadId: 'AES-256-GCM',
    macId: 'HMAC-SHA-384',
    hashId: 'SHA3-256/SHAKE256',
    description: 'Regulated Cat-5 tier: ML-KEM-1024 + ECDH P-384 KEM, ML-DSA-87 signatures.',
    standards: 'FIPS 203/204; CNSA 2.0 Cat-5 (ML-KEM-1024, ML-DSA-87, AES-256, SHA-384).',
  },
  [SUITE_IDS.PS_5_HQC]: {
    id: SUITE_IDS.PS_5_HQC,
    status: 'pending-standardization',
    category: 5,
    preference: 90,
    kemId: KEM_IDS.HQC256,
    sigId: SIG_IDS.ML_DSA_87,
    aeadId: 'AES-256-GCM',
    macId: 'HMAC-SHA-384',
    hashId: 'SHA3-256/SHAKE256',
    description: 'Agility: code-based HQC-256 backup KEM (non-lattice diversity).',
    standards:
      'HQC selected 2025-03-11 → NIST PQC standard (FIPS number TBD; draft ~2026, final 2027). PENDING.',
  },
  [SUITE_IDS.PS_5_FN]: {
    id: SUITE_IDS.PS_5_FN,
    status: 'not-load-bearing',
    category: 5,
    preference: 95,
    kemId: KEM_IDS.MLKEM1024_P384,
    sigId: SIG_IDS.FN_DSA_1024,
    aeadId: 'AES-256-GCM',
    macId: 'HMAC-SHA-384',
    hashId: 'SHA3-256/SHAKE256',
    description: 'Agility: compact Falcon/FN-DSA receipts (enclave-only, never load-bearing).',
    standards: 'FIPS 206 (FN-DSA) forthcoming/draft as of June 2026. NOT LOAD-BEARING.',
  },
}

/** Return suite metadata for an id, or throw {@link UnknownSuiteError}. */
export function getSuite(id: string): Suite {
  const suite = SUITES[id]
  if (!suite) throw new UnknownSuiteError(id)
  return suite
}

/** All registered suites, including pending/non-active ones. */
export function allSuites(): Suite[] {
  return Object.values(SUITES)
}

/** Suite ids that are active (safe to negotiate and use today). */
export function activeSuiteIds(): string[] {
  return allSuites()
    .filter((s) => s.status === 'active')
    .sort((a, b) => a.preference - b.preference)
    .map((s) => s.id)
}

/**
 * Negotiate the most-preferred *active* suite supported by both peers.
 * Preference is by ascending `preference` value (PS-5 over PS-1). Throws
 * {@link NoCommonSuiteError} if there is no active suite in common.
 */
export function negotiate(local: readonly string[], remote: readonly string[]): string {
  const remoteSet = new Set(remote)
  const candidates = activeSuiteIds().filter((id) => local.includes(id) && remoteSet.has(id))
  const best = candidates[0]
  if (best === undefined) throw new NoCommonSuiteError()
  return best
}

const NEGOTIATION_LABEL = 'polarseek/suite-negotiation'
const NEGOTIATION_VERSION = 1

/** The full negotiation context bound by {@link negotiationTranscript} (ADR-0029). */
export interface NegotiationContext {
  /**
   * A FRESH per-session binder — e.g. SHA3 of both peers' handshake nonces, or a unique handshake id.
   * Its freshness is what makes a PRIOR session's signed transcript un-replayable; the caller MUST
   * ensure it is unique per session (never reused).
   */
  readonly sessionId: Bytes
  /** Initiator long-term identity (hex public key) — binds the transcript to this peer pair. */
  readonly initiatorId: string
  /** Responder long-term identity (hex public key). */
  readonly responderId: string
  /** Initiator's full offered suite list, exactly as sent (never sorted). */
  readonly initiatorOffered: readonly string[]
  /** Responder's full offered suite list, exactly as sent. */
  readonly responderOffered: readonly string[]
  /** The suite both sides believe was chosen. */
  readonly chosen: string
}

/**
 * Downgrade-resistant negotiation transcript (ADR-0029). `negotiate` alone picks the best common
 * suite, but if the offered lists are exchanged over an UNAUTHENTICATED channel a MITM can STRIP the
 * stronger suites from a peer's offer, forcing a weaker common suite with nothing to detect it. This
 * commits a fresh `sessionId` + both peer identities + BOTH peers' FULL offered lists (exactly as
 * sent, by explicit initiator/responder role) + the chosen suite into one canonical hash. That
 * transcript MUST be signed in the first authenticated handshake message and cross-checked by the
 * peer: a stripped/reordered offer changes the transcript, so the signature over it no longer matches
 * the peer's recomputation and the downgrade is detected (the TLS-1.3 "Finished over the full
 * transcript" pattern).
 *
 * Binding `sessionId` defeats CROSS-SESSION replay of an old signed transcript; binding the two
 * identities defeats CROSS-PEER replay (council R3 review). Roles disambiguate whose list is whose,
 * and lists are bound AS-OFFERED (never sorted) — a strip is a removal, and the exact offered
 * sequence is what both sides must agree on.
 */
export function negotiationTranscript(ctx: NegotiationContext): Bytes {
  return SHA3_SHAKE256.digest(
    encodeCanonical([
      NEGOTIATION_LABEL,
      NEGOTIATION_VERSION,
      ctx.sessionId,
      ctx.initiatorId,
      ctx.responderId,
      [...ctx.initiatorOffered],
      [...ctx.responderOffered],
      ctx.chosen,
    ]),
  )
}

/**
 * Recompute the negotiation transcript from the locally-known view and constant-time-compare it to a
 * peer-supplied (signed) transcript. Returns false on ANY mismatch — a stripped/downgraded or
 * reordered offer, a different chosen suite, a different session, or a different peer pair (ADR-0029).
 * The caller MUST still verify the signature over `peerTranscript` independently; this only detects
 * the downgrade once that signature is confirmed authentic.
 */
export function verifyNegotiationTranscript(
  peerTranscript: Bytes,
  ctx: NegotiationContext,
): boolean {
  return constantTimeEqual(peerTranscript, negotiationTranscript(ctx))
}

/** Resolve the KEM for a suite (throws for pending suites when instantiated). */
export function kemFor(id: string): Kem {
  return getKem(getSuite(id).kemId)
}

/** Resolve the signature scheme for a suite. */
export function signerFor(id: string): SignatureScheme {
  return getSigner(getSuite(id).sigId)
}
