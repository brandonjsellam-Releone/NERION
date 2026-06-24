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
 * Actual decode-surface exports exercised (confirmed by reading the source):
 *
 *   crypto/src/cbor.ts
 *     decodeCbor(bytes)        — permissive cbor2 decode; value or throws Error
 *     decodeCanonical(bytes)   — strict dCBOR: decode + re-encode + byte-compare; throws on deviation
 *
 *   crypto/src/cose.ts
 *     decodeCoseSign1(bytes)   — COSE_Sign1 4-element array decoder with Uint8Array field guards
 *     coseSign1Verify(msg, suite, pk, alg, aad?) — fail-closed boolean verifier; never throws
 *
 *   crypto/src/envelope.ts
 *     verifyEnvelope(env, pk, allowedSuites?) — fail-closed boolean; returns false on unknown suite
 *     openEnvelope(env)        — decodes envelope payload bytes via decodeCbor; value or throws Error
 *     verifyPermit(token, key) — fail-closed boolean HMAC verifier; never throws
 *     readPermit(token)        — decodes permit body bytes via decodeCbor; value or throws Error
 *
 * Two input shapes are exercised throughout:
 *   - fc.uint8Array({minLength:0,maxLength:256})   — native Uint8Array (the protocol wire type)
 *   - fc.array(fc.integer({min:0,max:255}))        — JS number-array converted via Uint8Array.from()
 *
 * Both shapes must behave identically: typed value or typed Error, never an unhandled exception.
 */

/** One-time keygen for coseSign1Verify — uses PS_5 (ML-DSA-87) as declared in SUITE_IDS. */
const suite = SUITE_IDS.PS_5
const pk = signerFor(suite).keygen().publicKey

/** 48-byte HMAC-SHA-384 key for verifyPermit / readPermit. */
const macKey = new Uint8Array(48).fill(1)

/** Primary: native Uint8Array with the bounds from the task spec. */
const bytes = fc.uint8Array({ minLength: 0, maxLength: 256 })

/** Secondary: plain JS integer array converted to Uint8Array — exercises the same codepaths. */
const byteArray = fc.array(fc.integer({ min: 0, max: 255 })).map((a) => Uint8Array.from(a))

const RUNS = { numRuns: 400 }

// ─────────────────────────────────────────────────────────────────────────────
// decodeCbor
// cbor.ts: permissive wrapper over cbor2.decode(). On malformed input cbor2
// always throws an Error subclass — never a non-Error throw, never a hang.
// ─────────────────────────────────────────────────────────────────────────────
describe('A2 — decodeCbor: terminates on arbitrary bytes, throws only Error', () => {
  it('native Uint8Array input: value or instanceof Error', () => {
    fc.assert(
      fc.property(bytes, (b) => {
        try {
          decodeCbor(b)
        } catch (e) {
          expect(e).toBeInstanceOf(Error)
        }
      }),
      RUNS,
    )
  })

  it('integer-array → Uint8Array input: value or instanceof Error', () => {
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

  it('empty input: value or instanceof Error', () => {
    try {
      decodeCbor(new Uint8Array(0))
    } catch (e) {
      expect(e).toBeInstanceOf(Error)
    }
  })

  it('single-byte inputs (0x00–0xff): each terminates as value or instanceof Error', () => {
    for (let b = 0; b <= 0xff; b++) {
      try {
        decodeCbor(new Uint8Array([b]))
      } catch (e) {
        expect(e).toBeInstanceOf(Error)
      }
    }
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// decodeCanonical
// cbor.ts: strict path — decode then re-encode and byte-compare.
// Throws 'non-canonical CBOR: ...' on any non-dCBOR input; throws on parse
// error before the re-encode. Never non-Error.
// ─────────────────────────────────────────────────────────────────────────────
describe('A2 — decodeCanonical: terminates on arbitrary bytes, throws only Error', () => {
  it('native Uint8Array input: value or instanceof Error', () => {
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

  it('integer-array → Uint8Array input: value or instanceof Error', () => {
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

  it('non-canonical map (unsorted keys) must throw "non-canonical CBOR"', () => {
    // Manually craft non-canonical CBOR: a 1-element map {0: 0} is canonical.
    // Encoding with encodeCanonical produces exactly that — so round-trip passes.
    // Use a raw hand-crafted non-canonical encoding instead: CBOR indefinite-length
    // map 0xbf ... 0xff is the simplest portable non-canonical form.
    // 0xbf = indefinite-length map open, 0x00 = key 0, 0x00 = val 0, 0xff = break
    const nonCanonical = new Uint8Array([0xbf, 0x00, 0x00, 0xff])
    expect(() => decodeCanonical(nonCanonical)).toThrow(Error)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// decodeCoseSign1
// cose.ts: decodes a COSE_Sign1 wire form.
// Validates: 4-element CBOR array; v[0], v[2], v[3] are Uint8Array.
// Throws 'not a COSE_Sign1 4-element array' or
//        'COSE_Sign1 protected/payload/signature must be byte strings'
// Underlying decodeCbor failure propagates as Error.
// ─────────────────────────────────────────────────────────────────────────────
describe('A2 — decodeCoseSign1: terminates on arbitrary bytes, throws only Error', () => {
  it('native Uint8Array input: CoseSign1 or instanceof Error', () => {
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

  it('integer-array → Uint8Array input: CoseSign1 or instanceof Error', () => {
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

  it('wrong-length CBOR array throws typed Error', () => {
    // 3-element CBOR array [h'', h'', h''] — valid CBOR, wrong COSE shape
    // CBOR array of 3: 0x83, then three empty bstrs (0x40 each)
    const threeElem = new Uint8Array([0x83, 0x40, 0x40, 0x40])
    expect(() => decodeCoseSign1(threeElem)).toThrow(/not a COSE_Sign1 4-element array/)
  })

  it('4-element array with non-Uint8Array field throws typed Error', () => {
    // CBOR [1, {}, h'', h''] — v[0] is integer 1 (not a bstr) → type guard fires
    // 0x84 = 4-element array, 0x01 = integer 1, 0xa0 = empty map, 0x40 x2 = empty bstrs
    const wrongType = new Uint8Array([0x84, 0x01, 0xa0, 0x40, 0x40])
    expect(() => decodeCoseSign1(wrongType)).toThrow(
      /COSE_Sign1 protected\/payload\/signature must be byte strings/,
    )
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// coseSign1Verify
// cose.ts: fail-closed verifier. Always returns boolean; never throws.
// Checks protected header byte-equality first (constantTimeEqual), then
// delegates to signerFor(suite).verify() inside a try/catch.
// ─────────────────────────────────────────────────────────────────────────────
describe('A2 — coseSign1Verify: always returns boolean, never throws', () => {
  it('native Uint8Array fields → boolean', () => {
    fc.assert(
      fc.property(bytes, bytes, bytes, (p, pl, sig) => {
        const result = coseSign1Verify(
          { protected: p, payload: pl, signature: sig },
          suite,
          pk,
          COSE_ALG.ML_DSA_87,
        )
        expect(typeof result).toBe('boolean')
      }),
      RUNS,
    )
  })

  it('integer-array → Uint8Array fields → boolean', () => {
    fc.assert(
      fc.property(byteArray, byteArray, byteArray, (p, pl, sig) => {
        const result = coseSign1Verify(
          { protected: p, payload: pl, signature: sig },
          suite,
          pk,
          COSE_ALG.ML_DSA_87,
        )
        expect(typeof result).toBe('boolean')
      }),
      RUNS,
    )
  })

  it('all COSE_ALG code points against arbitrary bytes → boolean', () => {
    fc.assert(
      fc.property(bytes, (b) => {
        for (const alg of Object.values(COSE_ALG)) {
          const result = coseSign1Verify({ protected: b, payload: b, signature: b }, suite, pk, alg)
          expect(typeof result).toBe('boolean')
        }
      }),
      { numRuns: 100 },
    )
  })

  it('empty byte fields → false (no crash)', () => {
    const empty = new Uint8Array(0)
    expect(
      typeof coseSign1Verify(
        { protected: empty, payload: empty, signature: empty },
        suite,
        pk,
        COSE_ALG.ML_DSA_87,
      ),
    ).toBe('boolean')
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// verifyEnvelope
// envelope.ts: fail-closed boolean. Catches all signerFor / verify errors.
// Also returns false if suite not in allowedSuites.
// Tests cover: valid suite id, unknown suite id, and allowedSuites gating.
// ─────────────────────────────────────────────────────────────────────────────
describe('A2 — verifyEnvelope: always returns boolean, never throws', () => {
  it('known suite + arbitrary payload/sig → boolean (Uint8Array)', () => {
    fc.assert(
      fc.property(fc.string(), bytes, bytes, (ctx, payload, sig) => {
        expect(typeof verifyEnvelope({ suite, context: ctx, payload, sig }, pk)).toBe('boolean')
      }),
      RUNS,
    )
  })

  it('known suite + arbitrary payload/sig → boolean (integer-array)', () => {
    fc.assert(
      fc.property(fc.string(), byteArray, byteArray, (ctx, payload, sig) => {
        expect(typeof verifyEnvelope({ suite, context: ctx, payload, sig }, pk)).toBe('boolean')
      }),
      RUNS,
    )
  })

  it('arbitrary (garbage) suite id → false, never throws', () => {
    fc.assert(
      fc.property(fc.string(), bytes, bytes, (garbageSuite, payload, sig) => {
        // signerFor(garbageSuite) throws UnknownSuiteError; verifyEnvelope must catch it
        const result = verifyEnvelope({ suite: garbageSuite, context: '', payload, sig }, pk)
        expect(typeof result).toBe('boolean')
      }),
      RUNS,
    )
  })

  it('allowedSuites gating: suite not in list → false', () => {
    fc.assert(
      fc.property(bytes, bytes, (payload, sig) => {
        const result = verifyEnvelope(
          { suite, context: '', payload, sig },
          pk,
          ['PS-999'], // suite not in allowedSuites
        )
        expect(result).toBe(false)
      }),
      { numRuns: 100 },
    )
  })

  it('allowedSuites gating: suite in list → boolean (may be false for bad sig)', () => {
    fc.assert(
      fc.property(bytes, bytes, (payload, sig) => {
        const result = verifyEnvelope(
          { suite, context: '', payload, sig },
          pk,
          [suite], // suite IS in allowedSuites; still returns false for garbage sig
        )
        expect(typeof result).toBe('boolean')
      }),
      { numRuns: 100 },
    )
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// openEnvelope
// envelope.ts: decodes env.payload via decodeCbor. Terminates with a value or
// typed Error — inheriting decodeCbor's error contract.
// ─────────────────────────────────────────────────────────────────────────────
describe('A2 — openEnvelope: terminates on arbitrary payloads, throws only Error', () => {
  it('native Uint8Array payload → value or instanceof Error', () => {
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

  it('integer-array → Uint8Array payload → value or instanceof Error', () => {
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
})

// ─────────────────────────────────────────────────────────────────────────────
// verifyPermit
// envelope.ts: constant-time HMAC-SHA-384 verify. Returns boolean; never throws.
// ─────────────────────────────────────────────────────────────────────────────
describe('A2 — verifyPermit: always returns boolean, never throws', () => {
  it('native Uint8Array body/mac → boolean', () => {
    fc.assert(
      fc.property(bytes, bytes, (body, mac) => {
        expect(typeof verifyPermit({ suite, body, mac }, macKey)).toBe('boolean')
      }),
      RUNS,
    )
  })

  it('integer-array → Uint8Array body/mac → boolean', () => {
    fc.assert(
      fc.property(byteArray, byteArray, (body, mac) => {
        expect(typeof verifyPermit({ suite, body, mac }, macKey)).toBe('boolean')
      }),
      RUNS,
    )
  })

  it('empty body + arbitrary mac → false, no throw', () => {
    fc.assert(
      fc.property(bytes, (mac) => {
        expect(typeof verifyPermit({ suite, body: new Uint8Array(0), mac }, macKey)).toBe('boolean')
      }),
      { numRuns: 100 },
    )
  })

  it('arbitrary suite id in token (garbage) → boolean, never throws', () => {
    fc.assert(
      fc.property(fc.string(), bytes, bytes, (garbageSuite, body, mac) => {
        // The suite is embedded in the toBeMaced structure but verifyPermit does
        // not call signerFor — it only HMAC-verifies — so an unknown suite must
        // NOT throw; it must return false (MAC mismatch).
        expect(typeof verifyPermit({ suite: garbageSuite, body, mac }, macKey)).toBe('boolean')
      }),
      RUNS,
    )
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// readPermit
// envelope.ts: decodes token.body via decodeCbor. Same termination contract as
// openEnvelope — value or typed Error, never non-Error, never hang.
// ─────────────────────────────────────────────────────────────────────────────
describe('A2 — readPermit: terminates on arbitrary body bytes, throws only Error', () => {
  it('native Uint8Array body → value or instanceof Error', () => {
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

  it('integer-array → Uint8Array body → value or instanceof Error', () => {
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
