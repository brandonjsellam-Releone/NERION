// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Signed envelopes (COSE-like) and Plane-1 PermitTokens.
 *
 * - {@link signEnvelope}/{@link verifyEnvelope}: a SuiteID-tagged, PQ-signed
 *   object used on the nearline plane (receipts, capabilities). The signature
 *   covers a domain-separated, canonically-encoded "to-be-signed" structure so
 *   it cannot be re-interpreted in another context.
 *
 * - {@link issuePermit}/{@link verifyPermit}: the hot-path PermitToken, MAC'd
 *   with a session key (HMAC-SHA-384). NO per-action PQ signing and NO network
 *   round-trip — exactly as the three-plane spec requires for Plane 1.
 *
 * Both bind their SuiteID into the authenticated bytes, so a downgrade to a
 * weaker suite changes the signed/MAC'd transcript and fails verification.
 */

import type { Bytes } from './types.js'
import { encodeCanonical, decodeCbor } from './cbor.js'
import { signerFor } from './suites.js'
import { HMAC_SHA384 } from './symmetric.js'

const SIGNED_CONTEXT = 'PolarSeek-Signed-v1'
const PERMIT_CONTEXT = 'PolarSeek-Permit-v1'

export interface SignedEnvelope {
  /** SuiteID that produced `sig`. */
  readonly suite: string
  /** Free-form domain string binding the signature to a usage context. */
  readonly context: string
  /** Canonical CBOR bytes of the application payload. */
  readonly payload: Bytes
  /** Signature over the to-be-signed structure. */
  readonly sig: Bytes
}

export interface PermitToken {
  readonly suite: string
  /** Canonical CBOR bytes of the permit claims. */
  readonly body: Bytes
  /** HMAC-SHA-384 over the to-be-MAC'd structure. */
  readonly mac: Bytes
}

function toBeSigned(suite: string, context: string, payload: Bytes): Bytes {
  return encodeCanonical([SIGNED_CONTEXT, suite, context, payload])
}

function toBeMaced(suite: string, body: Bytes): Bytes {
  return encodeCanonical([PERMIT_CONTEXT, suite, body])
}

/**
 * Sign a payload using an arbitrary signing function over the to-be-signed
 * bytes. This is the hook that lets keys live behind a custody provider
 * (HSM / KMS) — see keystore/. `signFn` receives the exact bytes to sign.
 */
export function signEnvelopeWith(
  payload: unknown,
  suite: string,
  signFn: (toBeSigned: Bytes) => Bytes,
  context = '',
): SignedEnvelope {
  const payloadBytes = encodeCanonical(payload)
  const sig = signFn(toBeSigned(suite, context, payloadBytes))
  return { suite, context, payload: payloadBytes, sig }
}

/** Sign a payload under a suite's signature scheme, producing an envelope. */
export function signEnvelope(
  payload: unknown,
  suite: string,
  secretKey: Bytes,
  context = '',
): SignedEnvelope {
  return signEnvelopeWith(payload, suite, (tbs) => signerFor(suite).sign(tbs, secretKey), context)
}

/**
 * Verify an envelope against a public key. Returns false on any mismatch.
 *
 * If `allowedSuites` is supplied, the envelope's self-declared SuiteID must be
 * in it — preventing a relying party from inferring trust solely from a
 * self-declared suite (cross-suite downgrade, PS-CRYPTO-01). An unknown or
 * not-yet-implemented suite yields a clean `false`, never an exception
 * (PS-CRYPTO-02).
 */
export function verifyEnvelope(
  env: SignedEnvelope,
  publicKey: Bytes,
  allowedSuites?: readonly string[],
): boolean {
  if (allowedSuites !== undefined && !allowedSuites.includes(env.suite)) return false
  try {
    const signer = signerFor(env.suite)
    return signer.verify(env.sig, toBeSigned(env.suite, env.context, env.payload), publicKey)
  } catch {
    return false
  }
}

/** Decode an envelope's payload. Caller MUST verify first. */
export function openEnvelope(env: SignedEnvelope): unknown {
  return decodeCbor(env.payload)
}

/** Issue a hot-path PermitToken MAC'd with a session key. */
export function issuePermit(claims: unknown, suite: string, sessionKey: Bytes): PermitToken {
  const body = encodeCanonical(claims)
  const mac = HMAC_SHA384.compute(sessionKey, toBeMaced(suite, body))
  return { suite, body, mac }
}

/** Constant-time verify of a PermitToken against a session key. */
export function verifyPermit(token: PermitToken, sessionKey: Bytes): boolean {
  return HMAC_SHA384.verify(sessionKey, toBeMaced(token.suite, token.body), token.mac)
}

/** Decode a PermitToken's claims. Caller MUST verify first. */
export function readPermit(token: PermitToken): unknown {
  return decodeCbor(token.body)
}
