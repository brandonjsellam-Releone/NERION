// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import {
  totalStake,
  totalStakeBig,
  safeStake,
  isWellFormedStakeSet,
  viewChangeMessage,
  verifyViewChangeCert,
  GENESIS_PREV,
} from '../src/index.js'
import type { ValidatorSet, TimeoutVote, ViewChangeCert } from '../src/index.js'

/**
 * LEDGER-PRECISION-004 (Team Apex sweep): the -001/-002 fixes made the >=2/3 finality
 * cross-multiply exact but left BOTH operands summed in IEEE-754 — the counted stake (`stake += s`)
 * and the total (`totalStake()`), so past 2^53 either side could pre-round and the inequality could
 * flip (a sub-2/3 view-change cert accepted). Finality + sortition now sum stake as `totalStakeBig`.
 */
const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)
const MAX = 9007199254740991n // 2^53 - 1, the largest exactly-representable Number integer

describe('LEDGER-PRECISION-004 — exact bigint stake at the finality decision points', () => {
  it('totalStakeBig is exact where the Number sum rounds past 2^53', () => {
    const set: ValidatorSet = {
      validators: [
        { pubkey: 'a', stake: MAX },
        { pubkey: 'b', stake: MAX },
        { pubkey: 'c', stake: 5n },
      ],
    }
    expect(totalStakeBig(set)).toBe(18014398509481987n) // MAX + MAX + 5, exact
    // R5 (ADR-0027): stake is bigint, so totalStake itself is now exact past 2^53 — it AGREES with
    // totalStakeBig (the float-rounding gap this test once guarded against is structurally closed).
    expect(totalStake(set)).toBe(totalStakeBig(set))
  })

  it('verifyViewChangeCert is exact at stakes whose total exceeds 2^53', () => {
    const v = [0, 1, 2].map((i) => signer.keygen(new Uint8Array(32).fill(10 + i)))
    const set: ValidatorSet = {
      validators: v.map((k) => ({ pubkey: bytesToHex(k.publicKey), stake: MAX })),
    }
    const voteOf = (k: { secretKey: Uint8Array; publicKey: Uint8Array }): TimeoutVote => ({
      height: 0,
      prevHash: GENESIS_PREV,
      round: 0,
      validator: bytesToHex(k.publicKey),
      suite,
      sig: signer.sign(viewChangeMessage(suite, 0, GENESIS_PREV, 0), k.secretKey),
    })
    // 2 of 3 equal-stake validators = exactly 2/3 of a > 2^53 total -> finalize (boundary inclusive).
    const twoThirds: ViewChangeCert = { round: 0, votes: [voteOf(v[0]!), voteOf(v[1]!)] }
    expect(verifyViewChangeCert(set, suite, 0, GENESIS_PREV, 0, twoThirds)).toBe(true)
    // 1 of 3 = 1/3 < 2/3 -> reject, even at this magnitude.
    const oneThird: ViewChangeCert = { round: 0, votes: [voteOf(v[0]!)] }
    expect(verifyViewChangeCert(set, suite, 0, GENESIS_PREV, 0, oneThird)).toBe(false)
  })

  it('fails CLOSED on a malformed set (negative stake cannot lower the threshold) — council review', () => {
    const k = [0, 1].map((i) => signer.keygen(new Uint8Array(32).fill(30 + i)))
    // A negative stake would shrink a Number total; silently zeroing it would lower the 2/3 bar.
    const malformed: ValidatorSet = {
      validators: [
        { pubkey: bytesToHex(k[0]!.publicKey), stake: 10n },
        { pubkey: bytesToHex(k[1]!.publicKey), stake: -5n },
      ],
    }
    const votes = k.map((kp) => ({
      height: 0,
      prevHash: GENESIS_PREV,
      round: 0,
      validator: bytesToHex(kp.publicKey),
      suite,
      sig: signer.sign(viewChangeMessage(suite, 0, GENESIS_PREV, 0), kp.secretKey),
    }))
    // Even a unanimous cert must NOT finalize against a malformed set.
    expect(verifyViewChangeCert(malformed, suite, 0, GENESIS_PREV, 0, { round: 0, votes })).toBe(
      false,
    )
  })

  it('fails CLOSED (no throw) on a RUNTIME non-bigint stake — council R5 review', () => {
    // The TS type says bigint, but a verifier-supplied set decoded from untrusted bytes could carry a
    // `number`. `number >= 0n` is TRUE (relational coercion), so a `>= 0n`-only predicate would pass
    // it and then THROW `bigint + number` in the accumulation — an uncontrolled crash, NOT a
    // fail-closed verdict. isWellFormedStakeSet + safeStake must reject it cleanly without throwing.
    const k = [0, 1].map((i) => signer.keygen(new Uint8Array(32).fill(50 + i)))
    const malformed = {
      validators: [
        { pubkey: bytesToHex(k[0]!.publicKey), stake: 10 as unknown as bigint }, // runtime number!
        { pubkey: bytesToHex(k[1]!.publicKey), stake: 10n },
      ],
    } as ValidatorSet
    const votes = k.map((kp) => ({
      height: 0,
      prevHash: GENESIS_PREV,
      round: 0,
      validator: bytesToHex(kp.publicKey),
      suite,
      sig: signer.sign(viewChangeMessage(suite, 0, GENESIS_PREV, 0), kp.secretKey),
    }))
    const cert = { round: 0, votes }
    expect(() => verifyViewChangeCert(malformed, suite, 0, GENESIS_PREV, 0, cert)).not.toThrow()
    expect(verifyViewChangeCert(malformed, suite, 0, GENESIS_PREV, 0, cert)).toBe(false)
    // The stake-reading helpers stay total-safe (no bigint+number throw); the number clamps to 0n.
    expect(() => totalStake(malformed)).not.toThrow()
    expect(totalStake(malformed)).toBe(10n)
  })

  it('safeStake + isWellFormedStakeSet reject EVERY non-bigint stake shape (council R5)', () => {
    // safeStake clamps anything that is not a NON-NEGATIVE BIGINT to 0n, without throwing.
    for (const bad of [10, 1.5, NaN, Infinity, '5', null, undefined, {}, [], true, -1n, -7n]) {
      expect(safeStake(bad as unknown)).toBe(0n)
    }
    expect(safeStake(0n)).toBe(0n)
    expect(safeStake(7n)).toBe(7n)
    // isWellFormedStakeSet fails CLOSED on any non-bigint / negative shape.
    for (const bad of [10, 1.5, '5', null, undefined, -1n]) {
      const set = { validators: [{ pubkey: 'a', stake: bad as unknown as bigint }] } as ValidatorSet
      expect(isWellFormedStakeSet(set)).toBe(false)
    }
    expect(isWellFormedStakeSet({ validators: [{ pubkey: 'a', stake: 0n }] } as ValidatorSet)).toBe(
      true,
    )
  })
})
