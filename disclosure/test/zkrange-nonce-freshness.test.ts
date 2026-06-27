// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Nonce / blinding freshness (audit-prep 2026-06-27 — ZK dossier P2).
 *
 * Prover-side randomness is load-bearing for zero-knowledge: a repeated or derandomized
 * Schnorr nonce (`kReal`, zkrange.ts:138) leaks the witness (ECDSA-class failure). This
 * test pins that proving is non-deterministic — two proofs of the SAME statement and
 * witness produce distinct transcripts (fresh bit-blinding and fresh nonces) — ruling out
 * an accidentally derandomized prover, while both still verify. It does not (and cannot)
 * prove `randomBytes` is a CSPRNG; that remains an auditor [ITEM].
 */

import { describe, it, expect } from 'vitest'
import { commit, proveBelow, verifyBelow, randomScalar } from '../src/zkrange.js'
import { bytesToHex } from '@noble/hashes/utils.js'

const N = 32

describe('range-proof prover randomness is fresh per proof (ZK dossier P2)', () => {
  const r = randomScalar()
  const C = commit(40n, r)

  it('two proofs of the same statement/witness differ, yet both verify', () => {
    const p1 = proveBelow(40n, r, 100n, N)
    const p2 = proveBelow(40n, r, 100n, N)

    // Fresh per-bit blinding ⇒ different bit commitments.
    const c1 = bytesToHex(p1.amount.commitments[0]!.toBytes())
    const c2 = bytesToHex(p2.amount.commitments[0]!.toBytes())
    expect(c1).not.toBe(c2)

    // Fresh Schnorr nonces ⇒ different responses (a derandomized prover would collide).
    expect(p1.amount.bits[0]!.s0).not.toBe(p2.amount.bits[0]!.s0)

    // Both are valid for the same statement.
    expect(verifyBelow(C, 100n, p1, N)).toBe(true)
    expect(verifyBelow(C, 100n, p2, N)).toBe(true)
  })
})
