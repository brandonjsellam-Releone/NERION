// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Standards-binding profile (ADR-0025, Phase A) -- additive, NO new crypto.
 *
 * Projects a Nerion action-permit onto the agent-identity standards the EU/IETF
 * are converging on: a canonical Action Manifest ("policy-carrying verb"), a
 * post-quantum did:key agent identifier, and a W3C Verifiable Credentials 2.0
 * rendering. The wire-frozen v:1 PermitToken (SuiteID Ps1) is untouched -- this is
 * a *projection*. The ZK delegation-chain attenuation (Phase B) is intentionally
 * NOT here: it is a flagged research-bet, audit-gated. See docs/FRONTIER.md.
 */

import { encodeCanonical, SHA3_SHAKE256 } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { Bytes } from '../../crypto/src/types.js'

// --- Action Manifest --------------------------------------------------------

export type RiskClass = 'T0' | 'T1' | 'T2' | 'T3'

export interface ActionProvenance {
  readonly tool?: string
  readonly model?: string
  readonly software?: string
}

/**
 * A canonical, machine-checkable description of one governed action. `verbId`
 * MUST be namespaced (e.g. "fin.payment.transfer"); free-text labels are rejected.
 * That namespacing is the structural defence against "semantic laundering"
 * (relabelling a dangerous verb as a harmless one) flagged in docs/FRONTIER.md.
 */
export interface ActionManifest {
  readonly verbId: string
  readonly authorityScope: string
  readonly riskClass: RiskClass
  readonly policyHash: string
  readonly replayDomain: string
  readonly expiry: number
  readonly preconditions?: readonly string[]
  readonly expectedEffects?: readonly string[]
  readonly provenance?: ActionProvenance
}

const MANIFEST_CTX = 'nerion/action-manifest/v1'

export class ActionManifestError extends Error {}

/** True iff `verbId` has >= 2 non-empty dot-separated segments. */
export function isNamespacedVerb(verbId: string): boolean {
  const parts = verbId.split('.')
  return parts.length >= 2 && parts.every((p) => p.length > 0)
}

/**
 * Deterministic, domain-separated dCBOR digest of a manifest. Throws on a
 * non-namespaced verbId. Any field difference yields a different digest, so a
 * relabelled verb cannot collide with the action it impersonates.
 */
export function manifestDigest(m: ActionManifest): Bytes {
  if (!isNamespacedVerb(m.verbId)) {
    throw new ActionManifestError(
      `verbId must be namespaced (e.g. "fin.payment.transfer"), got: ${JSON.stringify(m.verbId)}`,
    )
  }
  return SHA3_SHAKE256.digest(encodeCanonical([MANIFEST_CTX, m]))
}

// --- base58btc (multibase 'z') ----------------------------------------------

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

export function base58btcEncode(bytes: Bytes): string {
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  const digits: number[] = [0]
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i] as number
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8
      digits[j] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  let out = ''
  for (let z = 0; z < zeros; z++) out += '1'
  for (let k = digits.length - 1; k >= 0; k--) out += B58.charAt(digits[k] as number)
  return out
}

export function base58btcDecode(s: string): Bytes {
  let zeros = 0
  while (zeros < s.length && s.charAt(zeros) === '1') zeros++
  const bytes: number[] = [0]
  for (let i = zeros; i < s.length; i++) {
    const val = B58.indexOf(s.charAt(i))
    if (val < 0) throw new Error(`invalid base58 character: ${s.charAt(i)}`)
    let carry = val
    for (let j = 0; j < bytes.length; j++) {
      carry += (bytes[j] as number) * 58
      bytes[j] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }
  const out = new Uint8Array(zeros + bytes.length)
  for (let k = 0; k < bytes.length; k++) out[zeros + k] = bytes[bytes.length - 1 - k] as number
  return out
}

// --- did:key over a post-quantum public key ---------------------------------

/** Unsigned LEB128 varint (multicodec prefix encoding). */
function unsignedVarint(n: number): Bytes {
  if (n < 0 || !Number.isInteger(n)) {
    throw new Error('multicodec code must be a non-negative integer')
  }
  const out: number[] = []
  let v = n
  do {
    let b = v & 0x7f
    v = Math.floor(v / 128)
    if (v > 0) b |= 0x80
    out.push(b)
  } while (v > 0)
  return Uint8Array.from(out)
}

/**
 * `did:key:z<base58btc(varint(multicodec) || pubkey)>`.
 *
 * The caller MUST supply the registered multicodec code for the key's algorithm
 * (https://github.com/multiformats/multicodec). ML-DSA / SLH-DSA multicodec
 * assignments are still being finalised upstream, so this function deliberately
 * does NOT hard-code a possibly-wrong value -- the code is an explicit input.
 */
export function didKeyFromPublicKey(multicodec: number, publicKey: Bytes): string {
  const prefix = unsignedVarint(multicodec)
  const buf = new Uint8Array(prefix.length + publicKey.length)
  buf.set(prefix, 0)
  buf.set(publicKey, prefix.length)
  return `did:key:z${base58btcEncode(buf)}`
}

// --- W3C Verifiable Credentials 2.0 projection ------------------------------

export interface PermitCredentialInput {
  readonly issuerDid: string
  readonly subjectDid: string
  readonly manifest: ActionManifest
  /** ISO-8601 timestamp; supplied by the caller (the library stays deterministic). */
  readonly validFrom: string
  readonly id?: string
}

/**
 * Project a permit + Action Manifest as a W3C VC 2.0 data object (the unsigned
 * data model). Proof attachment is out of scope: Nerion's ML-DSA-87 receipt +
 * transparency-log inclusion is the proof carrier; this is the interoperable
 * *rendering*, not a second signature scheme.
 */
export function toVerifiableCredential(input: PermitCredentialInput): Record<string, unknown> {
  const credentialSubject: Record<string, unknown> = {
    id: input.subjectDid,
    actionManifest: input.manifest,
    manifestDigest: bytesToHex(manifestDigest(input.manifest)),
  }
  const vc: Record<string, unknown> = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'NerionActionPermit'],
    issuer: input.issuerDid,
    validFrom: input.validFrom,
    credentialSubject,
  }
  if (input.id !== undefined) vc['id'] = input.id
  return vc
}
