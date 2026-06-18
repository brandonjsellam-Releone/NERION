import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { issueRoot } from '../../capabilities/src/index.js'
import { buildReplayBundle, replay, DEFAULT_POLICY } from '../src/index.js'
import type { KernelInput } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)
const authority = signer.keygen()
const holder = signer.keygen()
const holderHex = bytesToHex(holder.publicKey)

const root = issueRoot(
  {
    subject: holderHex,
    actions: ['payment.transfer'],
    perActionCeiling: 1000,
    aggregateCap: 5000,
    counterparties: ['alice'],
    maxTier: 2,
    notBefore: 0,
    notAfter: 10_000_000_000,
    delegable: false,
  },
  suite,
  authority,
)

const mkInput = (amount: number, now: number, agg: number): KernelInput => ({
  intent: { type: 'payment.transfer', resource: 'acct://t', counterparty: 'alice', amount },
  capabilities: [root],
  policy: DEFAULT_POLICY,
  trustedRoots: [authority.publicKey],
  now,
  observedAggregate: agg,
  holder: holderHex,
})

describe('ReplayBundle determinism', () => {
  it('re-derives a byte-identical decision and receipt hash', () => {
    const bundle = buildReplayBundle(mkInput(500, 1000, 0))
    const a = replay(bundle)
    const b = replay(bundle)
    expect(a.decision).toEqual(b.decision)
    expect(a.receiptHash).toBe(b.receiptHash)
    expect(a.inputHash).toBe(b.inputHash)
    expect(a.decision.effect).toBe('allow')
  })

  it('builds byte-identical input bytes for the same logical input', () => {
    const x = buildReplayBundle(mkInput(500, 1000, 0)).inputBytes
    const y = buildReplayBundle(mkInput(500, 1000, 0)).inputBytes
    expect(Buffer.from(x)).toEqual(Buffer.from(y))
  })

  it('property: replay is deterministic across random scalar inputs', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 3000 }),
        fc.integer({ min: 0, max: 2000 }),
        fc.integer({ min: 0, max: 6000 }),
        (amount, now, agg) => {
          const bundle = buildReplayBundle(mkInput(amount, now, agg))
          const a = replay(bundle)
          const b = replay(bundle)
          expect(a.receiptHash).toBe(b.receiptHash)
          expect(a.decision).toEqual(b.decision)
        },
      ),
    )
  })

  it('different decisions produce different receipt hashes', () => {
    const allow = replay(buildReplayBundle(mkInput(500, 1000, 0))) // within ceiling
    const deny = replay(buildReplayBundle(mkInput(2000, 1000, 0))) // over ceiling
    expect(allow.decision.effect).toBe('allow')
    expect(deny.decision.effect).toBe('deny')
    expect(allow.receiptHash).not.toBe(deny.receiptHash)
  })
})
