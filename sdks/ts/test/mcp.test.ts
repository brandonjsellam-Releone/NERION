// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, randomBytes } from '../../../crypto/src/index.js'
import { issueRoot, type ActionIntent } from '../../../capabilities/src/index.js'
import { DEFAULT_POLICY } from '../../../kernel/src/index.js'
import { TransparencyLog } from '../../../translog/src/index.js'
import { SoftwareAttester } from '../../../attest/src/index.js'
import { PolarSeekNode, type Session } from '../../../planes/src/index.js'
import { PolarSeekClient, guardTool, type GuardContext } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const s = signerFor(suite)
const authority = s.keygen()
const agent = s.keygen()
const issuer = s.keygen()
const attesterKey = s.keygen()
const agentHex = bytesToHex(agent.publicKey)
const NOW = 1_750_000_000

const evidence = new SoftwareAttester(suite, attesterKey).produce('sess', agentHex, 'n0', NOW + 300)
const session: Session = { sessionId: 'sess', sessionKey: randomBytes(48), claims: evidence.claims }

const cap = issueRoot(
  {
    subject: agentHex,
    actions: ['payment.transfer'],
    perActionCeiling: 1000,
    aggregateCap: 5000,
    counterparties: ['vendor-acme'],
    maxTier: 2,
    notBefore: 0,
    notAfter: NOW + 86_400,
    delegable: false,
  },
  suite,
  authority,
)

const client = new PolarSeekClient(
  new PolarSeekNode({
    suite,
    policy: DEFAULT_POLICY,
    trustedRoots: [authority.publicKey],
    issuer,
    log: new TransparencyLog(),
    jurisdiction: 'US',
    permitTtlSeconds: 30,
  }),
)

interface PayArgs {
  to: string
  amount: number
}
const mapIntent = (_tool: string, a: PayArgs): ActionIntent => ({
  type: 'payment.transfer',
  resource: 'acct://treasury',
  counterparty: a.to,
  amount: a.amount,
})

const ctx: GuardContext = {
  capabilities: [cap],
  session,
  audience: 'acct://treasury',
  now: NOW,
  observedAggregate: 0,
}

describe('MCP tool-call adapter', () => {
  it('executes an allowed tool call and returns its receipt', async () => {
    let calls = 0
    const guarded = guardTool(client, mapIntent, async (_t, a: PayArgs) => {
      calls++
      return { ok: true, paid: a.amount }
    })
    const r = await guarded('pay', { to: 'vendor-acme', amount: 500 }, ctx)
    expect(r.allowed).toBe(true)
    expect(r.result).toEqual({ ok: true, paid: 500 })
    expect(r.receipt).not.toBeNull()
    expect(calls).toBe(1)
  })

  it('blocks a denied tool call WITHOUT executing the handler', async () => {
    let calls = 0
    const guarded = guardTool(client, mapIntent, async (_t, a: PayArgs) => {
      calls++
      return { ok: true, paid: a.amount }
    })
    const r = await guarded('pay', { to: 'vendor-acme', amount: 5000 }, ctx) // over ceiling
    expect(r.allowed).toBe(false)
    expect(r.result).toBeNull()
    expect(calls).toBe(0) // the real action never ran
    expect(r.reasons.length).toBeGreaterThan(0)
  })

  it('blocks a disallowed counterparty', async () => {
    const guarded = guardTool(client, mapIntent, async () => ({ ok: true }))
    const r = await guarded('pay', { to: 'mallory', amount: 100 }, ctx)
    expect(r.allowed).toBe(false)
  })

  it('does NOT run the handler on a transform decision (MCP-TRANSFORM-001)', async () => {
    // A deployer configures payment.transfer as transform-gated (admitted only in
    // modified form). The kernel returns effect:'transform'; this adapter has no
    // transform applier, so it must refuse to run the original handler rather than
    // silently execute the un-attenuated action.
    const transformClient = new PolarSeekClient(
      new PolarSeekNode({
        suite,
        policy: { ...DEFAULT_POLICY, transformActions: ['payment.transfer'] },
        trustedRoots: [authority.publicKey],
        issuer,
        log: new TransparencyLog(),
        jurisdiction: 'US',
        permitTtlSeconds: 30,
      }),
    )
    let calls = 0
    const guarded = guardTool(transformClient, mapIntent, async (_t, a: PayArgs) => {
      calls++
      return { ok: true, paid: a.amount }
    })
    const r = await guarded('pay', { to: 'vendor-acme', amount: 500 }, ctx)
    expect(r.decision.effect).toBe('transform')
    expect(r.allowed).toBe(false)
    expect(r.result).toBeNull()
    expect(calls).toBe(0) // the un-transformed action never ran
  })

  it('enforces governance revocation through the guard (SDK-REVOKE-001)', async () => {
    let calls = 0
    const guarded = guardTool(client, mapIntent, async () => {
      calls++
      return { ok: true }
    })
    // Without revocation: allowed (sanity).
    expect((await guarded('pay', { to: 'vendor-acme', amount: 500 }, ctx)).allowed).toBe(true)
    // Revoke the capability's root id and pass it via the guard context.
    const revokedCtx: GuardContext = { ...ctx, revoked: [cap.chain[0]!.grant.id] }
    const r = await guarded('pay', { to: 'vendor-acme', amount: 500 }, revokedCtx)
    expect(r.allowed).toBe(false)
    expect(calls).toBe(1) // only the first (non-revoked) call ran
  })

  it('MCP-GUARD-THROW-001: a throwing mapIntent fails CLOSED as a deny, never rejecting or running the handler', async () => {
    // mapIntent is the integrator's arg-validation boundary and can only reject a malformed call by
    // throwing. The guard must convert that throw into a structured deny — not a rejected Promise that
    // a permissive dispatch loop could mishandle into a bypass.
    let calls = 0
    const throwingMap = (): ActionIntent => {
      throw new Error('malformed args')
    }
    const guarded = guardTool(client, throwingMap, async () => {
      calls++
      return { ok: true }
    })
    const r = await guarded('pay', { to: 'vendor-acme', amount: 500 }, ctx)
    expect(r.allowed).toBe(false)
    expect(r.result).toBeNull()
    expect(r.decision.effect).toBe('deny')
    expect(r.reasons.length).toBeGreaterThan(0)
    expect(calls).toBe(0) // the handler never ran
  })
})
