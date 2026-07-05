// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Selective disclosure for receipts — sound, with no custom crypto.
 *
 * A receipt commits to fields by hash. To disclose one field without revealing the
 * others, reveal its preimage; the verifier recomputes the commitment and matches
 * it. This is the "reveal nothing unnecessary" property using only the hash already
 * in the receipt — complementary to the ZK range proof in ./zkrange.
 *
 * SALTED (HIDING) MODE — RCPT‑001 (Team Apex audit, 2026‑06‑21; ADR‑0014). An
 * UNSALTED commitment `SHA3(canonical(value))` is binding but NOT hiding: if the
 * value has low entropy and known structure (e.g. an intent's `amount`), anyone
 * holding the public commitment can brute‑force it by enumerating candidates and
 * matching the hash. Passing a high‑entropy `salt` folds it into the preimage so
 * the published commitment no longer leaks low‑entropy fields. The salt is kept
 * out of the public artifact (it is NOT in the receipt's signed body / log leaf)
 * and revealed only to authorized verifiers for disclosure. Same brute‑force class
 * as CB‑001 in ./commitbind.
 */

import { DOMAIN_TAGS, encodeCanonical, SHA3_SHAKE256, type Bytes } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'

/** Domain tag for salted commitments — separates them from any other SHA3 use. */
const SALT_DOMAIN = DOMAIN_TAGS.SALTED_COMMIT

/**
 * The commitment used in receipts: SHA3‑256 over the canonical encoding.
 *
 * - WITHOUT `salt`: `SHA3(canonical(value))` — binding only (legacy; fine for
 *   high‑entropy or non‑secret fields).
 * - WITH `salt` (RCPT‑001 / ADR‑0014): `SHA3(canonical({domain, salt, value}))` —
 *   binding AND hiding, so a low‑entropy `value` cannot be brute‑forced from the
 *   public commitment. dCBOR (sorted keys, definite lengths, byte‑string salt)
 *   makes the preimage unambiguous.
 */
export function commitField(value: unknown, salt?: Bytes): string {
  const preimage =
    salt === undefined ? encodeCanonical(value) : encodeCanonical({ d: SALT_DOMAIN, salt, value })
  return bytesToHex(SHA3_SHAKE256.digest(preimage))
}

/**
 * Verify a revealed value matches a committed hash (e.g. from a receipt). Pass the
 * same `salt` the commitment was built with (required for salted/hiding
 * commitments; the salt is the disclosure secret an authorized verifier is given).
 */
export function verifyDisclosure(
  committedHashHex: string,
  revealedValue: unknown,
  salt?: Bytes,
): boolean {
  return commitField(revealedValue, salt) === committedHashHex
}
