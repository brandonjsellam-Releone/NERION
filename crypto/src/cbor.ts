// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Canonical CBOR — the byte-exact serialization PolarSeek hashes and signs.
 *
 * Determinism is a load-bearing protocol property: a ReplayBundle must
 * re-derive a byte-identical receipt (build spec guardrail #5). We use cbor2's
 * deterministic-encoding (`dcbor`) profile, which enforces sorted map keys,
 * shortest-form integers, definite-length items, and canonical floats — so the
 * same logical value always encodes to the same bytes regardless of key order.
 */

import { encode, decode } from 'cbor2'
import type { Bytes } from './types.js'

/** Encode a value to deterministic (dCBOR) bytes. */
export function encodeCanonical(value: unknown): Bytes {
  // `dcbor: true` selects the deterministic core encoding profile.
  return encode(value, { dcbor: true })
}

/** Decode CBOR bytes back to a JS value (permissive — accepts non-canonical input). */
export function decodeCbor(bytes: Bytes): unknown {
  return decode(bytes)
}

/**
 * Strictly decode CANONICAL (dCBOR) bytes: decode, then RE-ENCODE and require the result to be
 * byte-identical to the input. This REJECTS every non-canonical encoding cbor2's permissive
 * `decode()` silently accepts — unsorted OR duplicate map keys, non-minimal integers,
 * indefinite-length items, and non-canonical floats. Any of these breaks the determinism the
 * receipt/replay invariant rests on; the sharpest is a DUPLICATE-KEY map, where CBOR decoders
 * disagree on first-vs-last value and so can split replay/consensus. Use on ANY externally-supplied
 * bytes whose DECODED value is subsequently trusted (R7 hardening).
 */
export function decodeCanonical(bytes: Bytes): unknown {
  const value = decode(bytes)
  const reencoded = encodeCanonical(value)
  if (reencoded.length !== bytes.length || !reencoded.every((b, i) => b === bytes[i])) {
    throw new Error(
      'non-canonical CBOR: input is not the deterministic encoding of its decoded value',
    )
  }
  return value
}

/**
 * Assert that a value round-trips through deterministic encoding to identical
 * bytes (encode → decode → encode). Returns the canonical bytes. Throws if the
 * re-encoding is not byte-identical, which would signal a determinism bug.
 */
export function canonicalRoundTrip(value: unknown): Bytes {
  const first = encodeCanonical(value)
  const second = encodeCanonical(decodeCbor(first))
  if (first.length !== second.length || !first.every((b, i) => b === second[i])) {
    throw new Error('canonical CBOR is not stable across round-trip')
  }
  return first
}
