// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * COSE_Sign1 (RFC 9052) over PolarSeek's post-quantum signatures — the standard
 * CBOR signing envelope that makes receipts/attestations byte-conformant to IETF
 * COSE, and the encoding layer that SCITT (signed statements + transparency
 * receipts) and RATS (EAT attestation results, RFC 9711 / RFC 9334) build on. This
 * closes the bespoke-envelope gap: a standard COSE / SCITT / RATS verifier can
 * consume these directly.
 *
 * Structure (RFC 9052 §4.2): COSE_Sign1 = [protected: bstr, unprotected: map,
 * payload: bstr/nil, signature: bstr]. The signed bytes are the Sig_structure
 * (§4.4): ["Signature1", body_protected, external_aad, payload], CBOR-encoded.
 * `alg` is protected-header label 1.
 *
 * Algorithm: ML-DSA-87 = COSE alg -50 (ML-DSA-44 = -48, ML-DSA-65 = -49). NOTE:
 * these code points are IANA PROVISIONAL via draft-ietf-cose-dilithium — NOT yet a
 * final RFC. Cited as provisional, the honest status (confirmed by the council).
 */

import { encodeCanonical, decodeCbor } from './cbor.js'
import { signerFor } from './suites.js'
import { constantTimeEqual } from './symmetric.js'
import type { Bytes } from './types.js'

/** COSE algorithm code points (IANA provisional; draft-ietf-cose-dilithium). */
export const COSE_ALG = {
  ML_DSA_44: -48,
  ML_DSA_65: -49,
  ML_DSA_87: -50,
} as const

/** EAT (RFC 9711) claim keys used here. */
export const EAT_CLAIM = {
  /** eat_nonce */
  nonce: 10,
} as const

const ALG_LABEL = 1
const SIG_CONTEXT = 'Signature1'

export interface CoseSign1 {
  /** bstr: the CBOR-encoded protected header map ({1: alg}). */
  readonly protected: Bytes
  readonly payload: Bytes
  readonly signature: Bytes
}

/** Deterministic protected header carrying just `alg` (label 1). */
function protectedHeader(alg: number): Bytes {
  return encodeCanonical(new Map<number, number>([[ALG_LABEL, alg]]))
}

/** The exact bytes signed for COSE_Sign1: enc(["Signature1", protected, aad, payload]). */
function toBeSigned(protectedBytes: Bytes, payload: Bytes, externalAad: Bytes): Bytes {
  return encodeCanonical([SIG_CONTEXT, protectedBytes, externalAad, payload])
}

/** Produce a COSE_Sign1 over `payload` under `suite`'s signature scheme. */
export function coseSign1(
  payload: Bytes,
  suite: string,
  secretKey: Bytes,
  alg: number,
  externalAad: Bytes = new Uint8Array(),
): CoseSign1 {
  const prot = protectedHeader(alg)
  const signature = signerFor(suite).sign(toBeSigned(prot, payload, externalAad), secretKey)
  return { protected: prot, payload, signature }
}

/**
 * Verify a COSE_Sign1. The protected header must declare EXACTLY `expectedAlg`
 * (byte-exact compare — no decode ambiguity), and the signature must verify over
 * the Sig_structure. Fail-closed on any mismatch or a malformed input.
 */
export function coseSign1Verify(
  msg: CoseSign1,
  suite: string,
  publicKey: Bytes,
  expectedAlg: number,
  externalAad: Bytes = new Uint8Array(),
): boolean {
  if (!constantTimeEqual(msg.protected, protectedHeader(expectedAlg))) return false
  try {
    return signerFor(suite).verify(
      msg.signature,
      toBeSigned(msg.protected, msg.payload, externalAad),
      publicKey,
    )
  } catch {
    return false
  }
}

/** Encode the (untagged) COSE_Sign1 wire form [protected, {}, payload, signature]. */
export function encodeCoseSign1(msg: CoseSign1): Bytes {
  return encodeCanonical([msg.protected, new Map(), msg.payload, msg.signature])
}

/** Decode a COSE_Sign1 wire form back into its parts. */
export function decodeCoseSign1(bytes: Bytes): CoseSign1 {
  const v = decodeCbor(bytes)
  if (!Array.isArray(v) || v.length !== 4) throw new Error('not a COSE_Sign1 4-element array')
  return { protected: v[0] as Bytes, payload: v[2] as Bytes, signature: v[3] as Bytes }
}

/**
 * Build a RATS/EAT attestation-result payload (a CBOR map of claims, keyed by the
 * EAT nonce) and sign it as a COSE_Sign1 with ML-DSA-87 — the byte-conformant form
 * a RATS Relying Party / SCITT verifier consumes.
 */
export function signEatResult(
  nonce: Bytes,
  claims: Readonly<Record<string, unknown>>,
  suite: string,
  secretKey: Bytes,
  alg: number = COSE_ALG.ML_DSA_87,
): CoseSign1 {
  const eat = new Map<number | string, unknown>([[EAT_CLAIM.nonce, nonce]])
  for (const [k, val] of Object.entries(claims)) eat.set(k, val)
  return coseSign1(encodeCanonical(eat), suite, secretKey, alg)
}
