// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import {
  decodeCbor,
  decodeCanonical,
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
 *
 * Two input shapes are exercised throughout:
 *   - fc.uint8Array({minLength:0,maxLength:256})   — native Uint8Array (the protocol wire type)
 *   - fc.array(fc.integer({min:0,max:255}))        — JS number-array, converted via Uint8Array.from()
 *
 * Both shapes must behave identically: typed value or typed Error, never an unhandled exception.
 */
const suite = SUITE_IDS.PS_5
const pk = signerFor(suite).keygen().publicKey
const macKey = new Uint8Array(48).fill(1)

/** Primary: native Uint8Array with the exact bounds from the task spec. */
const bytes = fc.uint8Array({ minLength: 0, maxLength: 256 })

/** Secondary: plain JS integer array converted to Uint8Array — exercises the same codepaths. */
const byteArray = fc.array(fc.integer({ min: 0, max: 255 })).map((a) => Uint8Array.from(a))

const RUNS = { numRuns: 400 }

describe('A2 — decoder/verifier fuzzing (never panic on hostile bytes)', () => {
  // ── decodeCbor ─────────────────────────────────────────────────────────────
  it('decodeCbor terminates with a value or a typed Error on arbitrary bytes (Uint8Array)', () => {
    fc.assert(
      fc.property(bytes, (b) => {
        try {
          decodeCbor(b)
        } catch (e) {
          // controlled rejection; cbor2 always throws Error subclasses
          expect(e).toBeInstanceOf(Error)
        }
      }),
      RUNS,
    )
  })

  it('decodeCbor terminates with a value or a typed Error on arbitrary integer-array inputs', () => {
    fc.assert(
      fc.property(byteArray, (b) => {
        try {
          decodeCbor(b)
        } catch (e) {
          expect(e).toBeInstanceOf(Error)
        }
      }),
      RUNS,
    )
  })

  // ── decodeCanonical ────────────────────────────────────────────────────────
  it('decodeCanonical terminates with a value or a typed Error on arbitrary bytes (Uint8Array)', () => {
    fc.assert(
      fc.property(bytes, (b) => {
        try {
          decodeCanonical(b)
        } catch (e) {
          expect(e).toBeInstanceOf(Error)
        }
      }),
      RUNS,
    )
  })

  it('decodeCanonical terminates with a value or a typed Error on arbitrary integer-array inputs', () => {
    fc.assert(
      fc.property(byteArray, (b) => {
        try {
          decodeCanonical(b)
        } catch (e) {
          expect(e).toBeInstanceOf(Error)
        }
      }),
      RUNS,
    )
  })

  // ── decodeCoseSign1 ────────────────────────────────────────────────────────
  it('decodeCoseSign1 terminates with a value or a typed Error on arbitrary bytes (Uint8Array)', () => {
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

  it('decodeCoseSign1 terminates with a value or a typed Error on arbitrary integer-array inputs', () => {
    fc.assert(
      fc.property(byteArray, (b) => {
        try {
          decodeCoseSign1(b)
        } catch (e) {
          expect(e).toBeInstanceOf(Error)
        }
      }),
      RUNS,
    )
  })

  // ── coseSign1Verify ────────────────────────────────────────────────────────
  it('coseSign1Verify returns a boolean and never throws on arbitrary fields (Uint8Array)', () => {
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

  it('coseSign1Verify returns a boolean and never throws on arbitrary fields (integer-array)', () => {
    fc.assert(
      fc.property(byteArray, byteArray, byteArray, (p, pl, sig) => {
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

  // ── verifyEnvelope ─────────────────────────────────────────────────────────
  it('verifyEnvelope returns a boolean and never throws, incl. garbage suite (Uint8Array)', () => {
    fc.assert(
      fc.property(fc.string(), bytes, bytes, (ctx, payload, sig) => {
        // valid suite id
        expect(typeof verifyEnvelope({ suite, context: ctx, payload, sig }, pk)).toBe('boolean')
        // garbage suite id: signerFor throws → must be caught → false
        expect(typeof verifyEnvelope({ suite: ctx, context: ctx, payload, sig }, pk)).toBe(
          'boolean',
        )
      }),
      RUNS,
    )
  })

  it('verifyEnvelope returns a boolean and never throws, incl. garbage suite (integer-array)', () => {
    fc.assert(
      fc.property(fc.string(), byteArray, byteArray, (ctx, payload, sig) => {
        expect(typeof verifyEnvelope({ suite, context: ctx, payload, sig }, pk)).toBe('boolean')
        expect(typeof verifyEnvelope({ suite: ctx, context: ctx, payload, sig }, pk)).toBe(
          'boolean',
        )
      }),
      RUNS,
    )
  })

  // ── verifyPermit ───────────────────────────────────────────────────────────
  it('verifyPermit returns a boolean and never throws on arbitrary body/mac (Uint8Array)', () => {
    fc.assert(
      fc.property(bytes, bytes, (body, mac) => {
        expect(typeof verifyPermit({ suite, body, mac }, macKey)).toBe('boolean')
      }),
      RUNS,
    )
  })

  it('verifyPermit returns a boolean and never throws on arbitrary body/mac (integer-array)', () => {
    fc.assert(
      fc.property(byteArray, byteArray, (body, mac) => {
        expect(typeof verifyPermit({ suite, body, mac }, macKey)).toBe('boolean')
      }),
      RUNS,
    )
  })

  // ── openEnvelope / readPermit ──────────────────────────────────────────────
  it('openEnvelope terminates on arbitrary payloads — value or typed Error (Uint8Array)', () => {
    fc.assert(
      fc.property(bytes, (b) => {
        try {
          openEnvelope({ suite, context: '', payload: b, sig: b })
        } catch (e) {
          expect(e).toBeInstanceOf(Error)
        }
      }),
      RUNS,
    )
  })

  it('openEnvelope terminates on arbitrary payloads — value or typed Error (integer-array)', () => {
    fc.assert(
      fc.property(byteArray, (b) => {
        try {
          openEnvelope({ suite, context: '', payload: b, sig: b })
        } catch (e) {
          expect(e).toBeInstanceOf(Error)
        }
      }),
      RUNS,
    )
  })

  it('readPermit terminates on arbitrary body/mac — value or typed Error (Uint8Array)', () => {
    fc.assert(
      fc.property(bytes, (b) => {
        try {
          readPermit({ suite, body: b, mac: b })
        } catch (e) {
          expect(e).toBeInstanceOf(Error)
        }
      }),
      RUNS,
    )
  })

  it('readPermit terminates on arbitrary body/mac — value or typed Error (integer-array)', () => {
    fc.assert(
      fc.property(byteArray, (b) => {
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
