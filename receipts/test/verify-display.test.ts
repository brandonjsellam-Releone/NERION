// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * G3 displayed-vs-signed: CLI must not print VERIFIED using unsigned wrapper
 * `decision.effect`/`tier`. Fixtures are constructed JSON — no signer, no ML-DSA.
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'
import { signedDisplayFields, verifiedPaint } from '../src/verify-display.js'

const CLI_PATH = fileURLToPath(new URL('../../tools/verify-receipt.mjs', import.meta.url))

function fixture(
  over: {
    decisionEffect?: string
    decisionTier?: number
    bodyEffect?: string
    bodyTier?: number
    omitDecision?: boolean
  } = {},
) {
  const body = {
    v: 1 as const,
    suite: 'PS-5',
    evaluatorVersion: 'test',
    effect: over.bodyEffect ?? 'allow',
    tier: over.bodyTier ?? 2,
    jurisdiction: 'US',
    timestamp: 1_750_000_000,
    commitments: {
      intent: 'aa',
      capability: 'bb',
      policy: 'cc',
      inputHash: 'dd',
      decisionHash: 'ee',
    },
  }
  const bundle: Record<string, unknown> = {
    receipt: { body },
  }
  if (!over.omitDecision) {
    bundle.decision = {
      effect: over.decisionEffect ?? 'allow',
      tier: over.decisionTier ?? 2,
      obligations: [],
    }
  }
  return { bundle, body }
}

/** Executable-code detector: wrapper decision painted in a VERIFIED-emitting file. */
export function paintsUnsignedWrapperDecisionAsVerified(source: string): boolean {
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
  const paintsWrapper = /b\.decision\s*\??\.\s*(effect|tier)/.test(code)
  const printsVerified = /VERIFIED/.test(code)
  return paintsWrapper && printsVerified
}

describe('G3 displayed-vs-signed (verify-receipt paint)', () => {
  it('G3: matching wrapper may paint VERIFIED only from signed ReceiptBody', () => {
    const { bundle, body } = fixture()
    const paint = verifiedPaint(bundle)
    expect(paint, 'FAIL: matching signed body must be paintable as verified').not.toBeNull()
    expect(paint?.effect).toBe(body.effect)
    expect(paint?.tier).toBe(body.tier)
    expect(signedDisplayFields(bundle).ok).toBe(true)
  })

  it('G3: omitted wrapper paints VERIFIED from signed ReceiptBody only', () => {
    const { bundle, body } = fixture({ omitDecision: true })
    const paint = verifiedPaint(bundle)
    expect(paint, 'FAIL: body-only bundle must be paintable as verified').not.toBeNull()
    expect(paint?.effect).toBe(body.effect)
    expect(paint?.tier).toBe(body.tier)
  })

  it('G3: swapped unsigned decision.effect must FAIL (not VERIFIED)', () => {
    const { bundle, body } = fixture({ decisionEffect: 'deny', bodyEffect: 'allow' })
    const verdict = signedDisplayFields(bundle)
    const paint = verifiedPaint(bundle)
    expect(verdict.ok, 'FAIL: unsigned wrapper decision.effect painted as VERIFIED').toBe(false)
    expect(paint, 'FAIL: swapped decision.effect restored verified paint').toBeNull()
    expect(verdict.signed?.effect).toBe(body.effect)
    expect(verdict.reasons.some((r) => r.includes('decision.effect') && r.includes('deny'))).toBe(
      true,
    )
  })

  it('G3: swapped unsigned decision.tier must FAIL (not VERIFIED)', () => {
    const { bundle, body } = fixture({ decisionTier: 9, bodyTier: 2 })
    const verdict = signedDisplayFields(bundle)
    const paint = verifiedPaint(bundle)
    expect(verdict.ok, 'FAIL: unsigned wrapper decision.tier painted as VERIFIED').toBe(false)
    expect(paint, 'FAIL: swapped decision.tier restored verified paint').toBeNull()
    expect(verdict.signed?.tier).toBe(body.tier)
    expect(verdict.reasons.some((r) => r.includes('decision.tier') && r.includes('9'))).toBe(true)
  })

  it('G3: painted verified effect/tier must equal signed ReceiptBody, never wrapper', () => {
    const { bundle, body } = fixture({
      decisionEffect: 'deny',
      decisionTier: 0,
      bodyEffect: 'allow',
      bodyTier: 2,
    })
    const paint = verifiedPaint(bundle)
    expect(paint, 'FAIL: wrapper decision.effect/tier painted as verified').toBeNull()
    const live = signedDisplayFields(bundle).signed
    expect(live?.effect).toBe(body.effect)
    expect(live?.tier).toBe(body.tier)
    expect(live?.effect).not.toBe('deny')
    expect(live?.tier).not.toBe(0)
  })

  it('G3: mutation that restores painting b.decision.effect/tier as verified must FAIL', () => {
    const cli = readFileSync(CLI_PATH, 'utf8')
    expect(
      paintsUnsignedWrapperDecisionAsVerified(cli),
      'FAIL: CLI paints unsigned b.decision.effect/tier as VERIFIED',
    ).toBe(false)
    expect(cli, 'FAIL: CLI does not gate paint through signedDisplayFields').toMatch(
      /signedDisplayFields/,
    )
    expect(cli, 'FAIL: CLI does not require verifiedPaint before VERIFIED').toMatch(/verifiedPaint/)

    // Historical mutation: restore wrapper painting next to VERIFIED.
    const mutated = cli.replace(
      /display\.signed\.effect,\s*['"]\/['"],\s*display\.signed\.tier/,
      "b.decision?.effect, '/', b.decision?.tier",
    )
    expect(
      paintsUnsignedWrapperDecisionAsVerified(mutated),
      'detector must catch restored b.decision paint',
    ).toBe(true)

    // Functional mutation: a helper that paints wrapper fields as the verified result.
    const { bundle, body } = fixture({ decisionEffect: 'deny', bodyEffect: 'allow' })
    const restoredPaint = {
      ok: true as const,
      result: 'VERIFIED',
      effect: (bundle.decision as { effect: string }).effect,
      tier: (bundle.decision as { tier: number }).tier,
    }
    expect(
      restoredPaint.ok &&
        restoredPaint.result === 'VERIFIED' &&
        restoredPaint.effect === body.effect &&
        restoredPaint.tier === body.tier,
      'FAIL: unsigned wrapper decision.effect/tier painted as VERIFIED',
    ).toBe(false)
    expect(verifiedPaint(bundle)).toBeNull()
  })

  it('G3: missing signed ReceiptBody must FAIL (not VERIFIED)', () => {
    expect(verifiedPaint({ decision: { effect: 'allow', tier: 2 } })).toBeNull()
    expect(signedDisplayFields({ decision: { effect: 'allow', tier: 2 } }).ok).toBe(false)
  })

  it('G3: JSON fixture with swapped decision.effect must FAIL (no signer)', () => {
    const raw = JSON.stringify({
      decision: { effect: 'deny', tier: 2 },
      receipt: {
        body: {
          v: 1,
          suite: 'PS-5',
          effect: 'allow',
          tier: 2,
          jurisdiction: 'US',
          evaluatorVersion: 'test',
          timestamp: 0,
          commitments: {},
        },
      },
    })
    const parsed = JSON.parse(raw) as unknown
    expect(
      verifiedPaint(parsed),
      'FAIL: JSON-swapped decision.effect painted as VERIFIED',
    ).toBeNull()
    expect(signedDisplayFields(parsed).ok).toBe(false)
  })
})
