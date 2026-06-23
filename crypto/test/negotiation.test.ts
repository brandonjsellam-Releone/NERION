// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  negotiate,
  negotiationTranscript,
  verifyNegotiationTranscript,
  SUITE_IDS,
} from '../src/index.js'
import type { NegotiationContext } from '../src/index.js'

/**
 * Suite-negotiation downgrade resistance (ADR-0029 / R3). `negotiate` faithfully picks the best common
 * suite from what it is GIVEN, so it cannot see a MITM that strips stronger suites from a peer's offer
 * over an unauthenticated channel. The negotiation transcript binds a fresh sessionId + both peer
 * identities + both full offered lists + the chosen suite; cross-checking it (after the signature is
 * verified) detects the downgrade, and the sessionId/identity binding defeats cross-session and
 * cross-peer signature replay (council R3 review).
 */
const { PS_1, PS_5 } = SUITE_IDS
const sid = (n: number): Uint8Array => new Uint8Array(32).fill(n) // stand-in fresh per-session binder

const base = (): NegotiationContext => ({
  sessionId: sid(1),
  initiatorId: 'init-pubkey',
  responderId: 'resp-pubkey',
  initiatorOffered: [PS_5, PS_1],
  responderOffered: [PS_5, PS_1],
  chosen: PS_5,
})

describe('suite-negotiation downgrade resistance (ADR-0029)', () => {
  it('matching context verifies; transcript is a 32-byte SHA3 commitment', () => {
    const t = negotiationTranscript(base())
    expect(t.length).toBe(32)
    expect(verifyNegotiationTranscript(t, base())).toBe(true)
  })

  it('detects a STRIPPED initiator offer (the downgrade negotiate() cannot see)', () => {
    const signed = negotiationTranscript(base()) // initiator signs over its FULL offer
    // A MITM strips PS-5 from the initiator's offer in flight → the responder's view is [PS-1].
    expect(verifyNegotiationTranscript(signed, { ...base(), initiatorOffered: [PS_1] })).toBe(false)
  })

  it('detects a responder-offer strip that silently downgrades negotiate()', () => {
    expect(negotiate([PS_5, PS_1], [PS_5, PS_1])).toBe(PS_5)
    expect(negotiate([PS_5, PS_1], [PS_1])).toBe(PS_1) // silent at the negotiate layer
    // The responder signs over its TRUE full offer + PS-5; the initiator (stripped view + chose PS-1)
    // recomputes and cannot match → downgrade DETECTED.
    const responderSigned = negotiationTranscript(base())
    expect(
      verifyNegotiationTranscript(responderSigned, {
        ...base(),
        responderOffered: [PS_1],
        chosen: PS_1,
      }),
    ).toBe(false)
  })

  it('detects a reordered offer and a swapped chosen suite', () => {
    const t = negotiationTranscript(base())
    expect(verifyNegotiationTranscript(t, { ...base(), initiatorOffered: [PS_1, PS_5] })).toBe(
      false,
    )
    expect(verifyNegotiationTranscript(t, { ...base(), chosen: PS_1 })).toBe(false)
  })

  it('defeats CROSS-SESSION replay: identical lists+chosen but a different sessionId → no match', () => {
    const s1 = negotiationTranscript(base())
    const s2 = negotiationTranscript({ ...base(), sessionId: sid(2) })
    expect(Buffer.from(s1)).not.toEqual(Buffer.from(s2))
    // an old session's signed transcript does not verify in a fresh session
    expect(verifyNegotiationTranscript(s1, { ...base(), sessionId: sid(2) })).toBe(false)
  })

  it('defeats CROSS-PEER replay: a different peer pair → no match', () => {
    const ab = negotiationTranscript(base())
    expect(verifyNegotiationTranscript(ab, { ...base(), responderId: 'other-peer' })).toBe(false)
    expect(verifyNegotiationTranscript(ab, { ...base(), initiatorId: 'other-peer' })).toBe(false)
  })
})
