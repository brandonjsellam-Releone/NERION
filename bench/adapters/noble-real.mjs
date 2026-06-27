// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * BENCH-01 adapter: "noble-real".
 *
 * Exercises Nerion's REAL load-bearing primitives through the same upstream
 * libraries the protocol depends on:
 *   - signatures            : ML-DSA-87 (FIPS 204, Cat-5)  — @noble/post-quantum
 *   - intent-commitment hash: SHA3-256                     — @noble/hashes
 *   - audience permit-key KDF: HKDF-SHA-384                — @noble/hashes
 *
 * These match the protocol's choices (crypto/src/sign.ts, crypto/src/envelope.ts).
 * This is a MEASUREMENT adapter, not the production kernel: the runner assembles
 * a faithful structural model of the "govern the verb" path (audience-key
 * derivation -> salted intent commitment -> permit sign/verify) so the primitive
 * costs can be benchmarked deterministically and adversarial bindings checked.
 *
 * The adapter interface is the extension point: a future `rust-ffi` adapter (the
 * Rust foundation) or a `dist-real` adapter (Nerion's own crypto/src wrappers via
 * `npm run build`) implements the same shape and the runner stays unchanged.
 *
 * UNAUDITED / pre-FTO. No audited, FIPS-validated, production, or
 * non-infringement claim is implied by any number this harness emits.
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha384 } from '@noble/hashes/sha2.js'

export function createAdapter() {
  return {
    name: 'noble-real',
    primitive: 'ML-DSA-87',
    hash: 'SHA3-256',
    kdf: 'HKDF-SHA-384',
    isProxy: false,

    /** Deterministic keypair from a 32-byte seed (reproducible across machines). */
    keygen(seed) {
      const { publicKey, secretKey } = ml_dsa87.keygen(seed)
      return { publicKey, secretKey }
    },
    sign(message, secretKey) {
      return ml_dsa87.sign(message, secretKey)
    },
    verify(signature, message, publicKey) {
      return ml_dsa87.verify(signature, message, publicKey)
    },
    sha3_256(data) {
      return sha3_256(data)
    },
    /** HKDF-SHA-384, mirroring the audience-bound permit-key derivation. */
    hkdfSha384(ikm, salt, info, length) {
      return hkdf(sha384, ikm, salt, info, length)
    },
  }
}
