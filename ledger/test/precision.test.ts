// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import {
  totalStake,
  totalStakeBig,
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
const MAX = 9007199254740991 // 2^53 - 1, the largest exactly-representable Number integer

describe('LEDGER-PRECISION-004 — exact bigint stake at the finality decision points', () => {
  it('totalStakeBig is exact where the Number sum rounds past 2^53', () => {
    const set: ValidatorSet = {
      validators: [
        { pubkey: 'a', stake: MAX },
        { pubkey: 'b', stake: MAX },
        { pubkey: 'c', stake: 5 },
      ],
    }
    expect(totalStakeBig(set)).toBe(18014398509481987n) // MAX + MAX + 5, exact
    // The Number reduce cannot represent that odd value past 2^53 — it is rounded, so the
    // bigint-of-the-float disagrees with the exact bigint sum (this is the gap being closed).
    expect(BigInt(totalStake(set))).not.toBe(totalStakeBig(set))
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
})
