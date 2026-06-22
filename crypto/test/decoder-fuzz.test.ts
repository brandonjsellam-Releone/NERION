// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import {
  decodeCbor,
  decodeCoseSign1,
  coseSign1Verify,
  verifyEnvelope,
  openEnvelope,
  verifyPermit,
  readPermit,
  signerFor,
  SUITE_IDS,
  COSE_ALG,
} from '../src/index.js'

/**
 * A2 (Team Apex sprint): decoder + verifier fuzzing. The stateless TRUST-BOUNDARY verifiers must
 * NEVER throw on hostile bytes — they return false/null — and the decoders must always TERMINATE
 * (a value, or a typed Error, never an uncaught non-Error / hang / OOB) on arbitrary or truncated
 * input. Complements the decode-surface hand-audit (DECODE-TYPE-001) by proving robustness over
 * randomized inputs rather than a handful of crafted vectors.
 */
const suite = SUITE_IDS.PS_5
const pk = signerFor(suite).keygen().publicKey
const macKey = new Uint8Array(48).fill(1)
const bytes = fc.uint8Array({ maxLength: 512 })
const RUNS = { numRuns: 400 }

describe('A2 — decoder/verifier fuzzing (never panic on hostile bytes)', () => {
  it('coseSign1Verify returns a boolean and never throws on arbitrary fields', () => {
    fc.assert(
      fc.property(bytes, bytes, bytes, (p, pl, sig) => {
        expect(
          typeof coseSign1Verify(
            { protected: p, payload: pl, signature: sig },
            suite,
            pk,
            COSE_ALG.ML_DSA_87,
          ),
        ).toBe('boolean')
      }),
      RUNS,
    )
  })

  it('verifyEnvelope returns a boolean and never throws (incl. a garbage suite)', () => {
    fc.assert(
      fc.property(fc.string(), bytes, bytes, (ctx, payload, sig) => {
        expect(typeof verifyEnvelope({ suite, context: ctx, payload, sig }, pk)).toBe('boolean')
        // a garbage suite id must be caught (signerFor throws -> false), not propagate
        expect(typeof verifyEnvelope({ suite: ctx, context: ctx, payload, sig }, pk)).toBe(
          'boolean',
        )
      }),
      RUNS,
    )
  })

  it('verifyPermit returns a boolean and never throws on arbitrary body/mac', () => {
    fc.assert(
      fc.property(bytes, bytes, (body, mac) => {
        expect(typeof verifyPermit({ suite, body, mac }, macKey)).toBe('boolean')
      }),
      RUNS,
    )
  })

  it('decodeCbor terminates with a value or a typed Error on arbitrary bytes', () => {
    fc.assert(
      fc.property(bytes, (b) => {
        try {
          decodeCbor(b)
        } catch (e) {
          expect(e).toBeInstanceOf(Error) // controlled rejection, not a crash/OOB
        }
      }),
      RUNS,
    )
  })

  it('decodeCoseSign1 terminates with a value or a typed Error on arbitrary bytes', () => {
    fc.assert(
      fc.property(bytes, (b) => {
        try {
          decodeCoseSign1(b)
        } catch (e) {
          expect(e).toBeInstanceOf(Error)
        }
      }),
      RUNS,
    )
  })

  it('openEnvelope / readPermit terminate on arbitrary payloads (value or typed Error)', () => {
    fc.assert(
      fc.property(bytes, (b) => {
        try {
          openEnvelope({ suite, context: '', payload: b, sig: b })
        } catch (e) {
          expect(e).toBeInstanceOf(Error)
        }
        try {
          readPermit({ suite, body: b, mac: b })
        } catch (e) {
          expect(e).toBeInstanceOf(Error)
        }
      }),
      RUNS,
    )
  })
})
