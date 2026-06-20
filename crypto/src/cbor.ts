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

/** Decode CBOR bytes back to a JS value. */
export function decodeCbor(bytes: Bytes): unknown {
  return decode(bytes)
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
