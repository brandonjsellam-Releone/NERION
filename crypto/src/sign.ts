// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Digital signature schemes.
 *
 *   PS-SIG/ML-DSA-87        general-purpose signatures (FIPS 204, Cat-5)
 *   PS-SIG/SLH-DSA-SHAKE-256f  long-term / root-of-trust signatures (FIPS 205)
 *
 * Falcon / FN-DSA (FIPS 206) is registered but NOT load-bearing: FIPS 206 is
 * still a forthcoming draft as of June 2026, so it must never be used for any
 * verifying authority until finalized and validated. See docs/adr/ADR-0001.
 */

import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { slh_dsa_shake_256f } from '@noble/post-quantum/slh-dsa.js'
import type { Bytes, SignatureScheme } from './types.js'
import { NotImplementedError } from './errors.js'

/** Structural shape of a noble Signer (ml_dsa*, slh_dsa_*). */
interface NobleSigner {
  keygen(seed?: Bytes): { publicKey: Bytes; secretKey: Bytes }
  sign(message: Bytes, secretKey: Bytes, opts?: { context?: Bytes }): Bytes
  verify(signature: Bytes, message: Bytes, publicKey: Bytes, opts?: { context?: Bytes }): boolean
  lengths: Record<string, number>
}

function wrap(id: string, impl: NobleSigner): SignatureScheme {
  return {
    id,
    lengths: { ...impl.lengths },
    keygen(seed) {
      const { publicKey, secretKey } = seed === undefined ? impl.keygen() : impl.keygen(seed)
      return { publicKey, secretKey }
    },
    // FIPS-204/205 context string (≤255 bytes) for domain separation. Omitting it
    // uses @noble's empty-context default — byte-identical to the prior 2-arg call,
    // so pinned no-context KATs are unchanged. Only pass opts when a context is given.
    sign(message, secretKey, context) {
      return context === undefined
        ? impl.sign(message, secretKey)
        : impl.sign(message, secretKey, { context })
    },
    verify(signature, message, publicKey, context) {
      return context === undefined
        ? impl.verify(signature, message, publicKey)
        : impl.verify(signature, message, publicKey, { context })
    },
  }
}

export const SIG_IDS = {
  ML_DSA_87: 'ML-DSA-87',
  SLH_DSA_SHAKE_256F: 'SLH-DSA-SHAKE-256f',
  /** FFT-over-NTRU signatures — pending FIPS 206. Not load-bearing. */
  FN_DSA_1024: 'FN-DSA-1024',
} as const

export type SigId = (typeof SIG_IDS)[keyof typeof SIG_IDS]

const REGISTRY: Record<string, () => SignatureScheme> = {
  [SIG_IDS.ML_DSA_87]: () => wrap(SIG_IDS.ML_DSA_87, ml_dsa87 as unknown as NobleSigner),
  [SIG_IDS.SLH_DSA_SHAKE_256F]: () =>
    wrap(SIG_IDS.SLH_DSA_SHAKE_256F, slh_dsa_shake_256f as unknown as NobleSigner),
  [SIG_IDS.FN_DSA_1024]: () => {
    throw new NotImplementedError(
      'FN-DSA-1024 (Falcon) signatures',
      'FIPS 206 final + a hardened constant-time Falcon implementation (draft as of June 2026)',
    )
  },
}

/** Instantiate a signer by id. Throws {@link NotImplementedError} for pending schemes. */
export function getSigner(id: string): SignatureScheme {
  const factory = REGISTRY[id]
  if (!factory) throw new NotImplementedError(`signer "${id}"`, 'register it in crypto/src/sign.ts')
  return factory()
}

/** Ids of signature schemes usable today (excludes not-load-bearing stubs). */
export function implementedSigIds(): string[] {
  return [SIG_IDS.ML_DSA_87, SIG_IDS.SLH_DSA_SHAKE_256F]
}
