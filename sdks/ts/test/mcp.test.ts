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
})
