// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Hybrid Key Encapsulation Mechanisms.
 *
 * PolarSeek only registers *hybrid* KEMs — a classical ECDH leg combined with a
 * PQ module-lattice leg via a vetted KDF combiner — so a break of either leg
 * alone does not reveal the shared secret. Constructions come straight from the
 * audited `@noble/post-quantum/hybrid` module; we never assemble our own
 * combiner (build spec guardrail: "never roll your own primitive").
 *
 *   PS-KEM/XWING   = X-Wing: X25519 + ML-KEM-768   (IETF draft, general tier)
 *   PS-KEM/MLKEM1024-P384 = ML-KEM-1024 + ECDH P-384 (CNSA 2.0 Cat-5 tier)
 *
 * Note on the spec's literal "X25519 + ML-KEM-1024": that pairing mismatches
 * security levels (X25519 ≈ Cat-1 classical vs ML-KEM-1024 Cat-5). For the
 * regulated tier we therefore pair ML-KEM-1024 with P-384, the CNSA-2.0
 * classical curve. See docs/adr/ADR-0001 and ADR-0002. HQC (code-based backup)
 * is registered but not yet implementable — see {@link ./stubs}.
 */

import { XWing, MLKEM1024P384 } from '@noble/post-quantum/hybrid.js'
import type { Bytes, Kem } from './types.js'
import { NotImplementedError } from './errors.js'

/** Structural shape of a noble KEM (XWing, MLKEM1024P384, ml_kem*, …). */
interface NobleKem {
  keygen(seed?: Bytes): { publicKey: Bytes; secretKey: Bytes }
  encapsulate(publicKey: Bytes, msg?: Bytes): { cipherText: Bytes; sharedSecret: Bytes }
  decapsulate(cipherText: Bytes, secretKey: Bytes): Bytes
  lengths: Record<string, number>
}

function wrap(id: string, impl: NobleKem): Kem {
  return {
    id,
    lengths: { ...impl.lengths },
    keygen(seed) {
      const { publicKey, secretKey } = seed === undefined ? impl.keygen() : impl.keygen(seed)
      return { publicKey, secretKey }
    },
    encapsulate(publicKey, coins) {
      const { cipherText, sharedSecret } =
        coins === undefined ? impl.encapsulate(publicKey) : impl.encapsulate(publicKey, coins)
      return { cipherText, sharedSecret }
    },
    decapsulate(cipherText, secretKey) {
      return impl.decapsulate(cipherText, secretKey)
    },
  }
}

export const KEM_IDS = {
  XWING: 'XWING-MLKEM768-X25519',
  MLKEM1024_P384: 'MLKEM1024-P384',
  /** Code-based backup KEM — pending FIPS 207 (HQC). Not yet implementable. */
  HQC256: 'HQC-256',
} as const

export type KemId = (typeof KEM_IDS)[keyof typeof KEM_IDS]

const REGISTRY: Record<string, () => Kem> = {
  [KEM_IDS.XWING]: () => wrap(KEM_IDS.XWING, XWing as unknown as NobleKem),
  [KEM_IDS.MLKEM1024_P384]: () =>
    wrap(KEM_IDS.MLKEM1024_P384, MLKEM1024P384 as unknown as NobleKem),
  [KEM_IDS.HQC256]: () => {
    throw new NotImplementedError(
      'HQC-256 KEM',
      'liboqs / NIST FIPS 207 reference once HQC is standardized (selected 2025-03-11, final ~2027)',
    )
  },
}

/** Instantiate a KEM by id. Throws {@link NotImplementedError} for pending KEMs. */
export function getKem(id: string): Kem {
  const factory = REGISTRY[id]
  if (!factory) throw new NotImplementedError(`KEM "${id}"`, 'register it in crypto/src/kem.ts')
  return factory()
}

/** Ids of KEMs that are actually usable today (excludes pending stubs). */
export function implementedKemIds(): string[] {
  return [KEM_IDS.XWING, KEM_IDS.MLKEM1024_P384]
}
