// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Selective disclosure for receipts — sound, with no custom crypto.
 *
 * A receipt commits to fields by hash (e.g. commitments.intent = SHA3(canonical
 * intent)). To disclose one field without revealing the others, reveal its
 * preimage; the verifier recomputes the commitment and matches it. This is the
 * "reveal nothing unnecessary" property using only the hash already in the
 * receipt — complementary to the ZK range proof in ./zkrange.
 */

import { encodeCanonical, SHA3_SHAKE256 } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'

/** The commitment used in receipts: SHA3-256 over the canonical encoding. */
export function commitField(value: unknown): string {
  return bytesToHex(SHA3_SHAKE256.digest(encodeCanonical(value)))
}

/** Verify a revealed value matches a committed hash (e.g. from a receipt). */
export function verifyDisclosure(committedHashHex: string, revealedValue: unknown): boolean {
  return commitField(revealedValue) === committedHashHex
}
