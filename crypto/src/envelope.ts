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
import { HMAC_SHA384, HKDF_SHA384 } from './symmetric.js'

const SIGNED_CONTEXT = 'PolarSeek-Signed-v1'
const PERMIT_CONTEXT = 'PolarSeek-Permit-v1'
const AUDIENCE_KDF_CONTEXT = 'PolarSeek-Permit-AudienceKDF-v1'

/** HMAC-SHA-384 key width (matches the PermitToken MAC tag width). */
const PERMIT_MAC_KEY_BYTES = 48

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

/**
 * Derive the audience-scoped PermitToken MAC key from a session secret.
 *
 * HKDF-SHA-384 binds the `audience` into `info` under a fixed domain separator;
 * `info` is canonical CBOR (length-prefixed, key-order-independent), so distinct
 * audiences never collide and the derivation cannot be confused across contexts.
 *
 * The derivation is one-way and per-audience independent: the issuer holds the
 * session secret and derives a key per audience, while each resource is
 * provisioned with ONLY `deriveAudiencePermitKey(sessionKey, itsAudience)`. A
 * resource cannot recover the session secret nor any sibling audience's key, so
 * it cannot re-MAC (forge) a permit for a different audience — closing the
 * cross-audience forgery PERMIT-001 (ADR-0015).
 */
export function deriveAudiencePermitKey(sessionKey: Bytes, audience: string): Bytes {
  const info = encodeCanonical([AUDIENCE_KDF_CONTEXT, audience])
  return HKDF_SHA384.derive(sessionKey, new Uint8Array(0), info, PERMIT_MAC_KEY_BYTES)
}

/** Issue a hot-path PermitToken MAC'd with a (per-audience) session key. */
export function issuePermit(claims: unknown, suite: string, sessionKey: Bytes): PermitToken {
  const body = encodeCanonical(claims)
  const mac = HMAC_SHA384.compute(sessionKey, toBeMaced(suite, body))
  return { suite, body, mac }
}

/** Constant-time verify of a PermitToken against a session key. */
export function verifyPermit(token: PermitToken, sessionKey: Bytes): boolean {
  return HMAC_SHA384.verify(sessionKey, toBeMaced(token.suite, token.body), token.mac)
}

/**
 * The root PermitToken MAC over (suite, body) under a session/audience key — i.e. the value
 * `issuePermit` puts in `mac` and `verifyPermit` checks. Exposed so the macaroon caveat layer
 * (planes/caveat.ts) can recompute it from the audience key WITHOUT the un-attenuated MAC ever
 * appearing in a forwarded attenuated permit (which would let a holder strip its caveats).
 */
export function permitMac(
  token: { readonly suite: string; readonly body: Bytes },
  key: Bytes,
): Bytes {
  return HMAC_SHA384.compute(key, toBeMaced(token.suite, token.body))
}

/** Decode a PermitToken's claims. Caller MUST verify first. */
export function readPermit(token: PermitToken): unknown {
  return decodeCbor(token.body)
}
