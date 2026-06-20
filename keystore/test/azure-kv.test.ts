// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { AzureKeyVaultSealer } from '../src/index.js'

/**
 * A mock Azure endpoint that issues a token, resolves the key version (kid), and
 * echoes wrap/unwrap values (an identity transform — enough to prove our request
 * shaping and base64url round-trip without a real vault).
 */
function mockAzure() {
  const calls: { url: string; init: RequestInit | undefined }[] = []
  const kid = 'https://v.vault.azure.net/keys/kek/abc123'
  const impl = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url)
    calls.push({ url: u, init })
    if (u.includes('/oauth2/v2.0/token')) {
      return new Response(JSON.stringify({ access_token: 'tok', expires_in: 3600 }), {
        status: 200,
      })
    }
    if (u.includes('/keys/kek?')) {
      return new Response(JSON.stringify({ key: { kid } }), { status: 200 })
    }
    if (u.startsWith(`${kid}/wrapkey`) || u.startsWith(`${kid}/unwrapkey`)) {
      const body = JSON.parse(String(init?.body)) as { alg: string; value: string }
      return new Response(JSON.stringify({ kid, value: body.value }), { status: 200 })
    }
    return new Response(JSON.stringify({ error: 'unexpected' }), { status: 404 })
  }) as unknown as typeof fetch
  return { impl, calls, kid }
}

describe('AzureKeyVaultSealer REST shaping', () => {
  it('authenticates, resolves the kid, and round-trips wrap/unwrap (base64url)', async () => {
    const { impl, calls, kid } = mockAzure()
    const sealer = new AzureKeyVaultSealer({
      tenantId: 't',
      clientId: 'c',
      clientSecret: 's',
      vaultUrl: 'https://v.vault.azure.net/',
      keyName: 'kek',
      fetchImpl: impl,
    })

    const seed = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 255])
    const back = await sealer.unwrap(await sealer.wrap(seed))
    expect(Array.from(back)).toEqual(Array.from(seed))

    const tokenCall = calls.find((c) => c.url.includes('/oauth2/v2.0/token'))
    expect(String(tokenCall?.init?.body)).toContain('grant_type=client_credentials')
    expect(String(tokenCall?.init?.body)).toContain(
      'scope=https%3A%2F%2Fvault.azure.net%2F.default',
    )

    const wrapCall = calls.find((c) => c.url.startsWith(`${kid}/wrapkey`))
    expect(wrapCall).toBeDefined()
    expect((JSON.parse(String(wrapCall?.init?.body)) as { alg: string }).alg).toBe('RSA-OAEP-256')
  })

  it('caches the token across operations (one token fetch for many ops)', async () => {
    const { impl, calls } = mockAzure()
    const sealer = new AzureKeyVaultSealer({
      tenantId: 't',
      clientId: 'c',
      clientSecret: 's',
      vaultUrl: 'https://v.vault.azure.net/',
      keyName: 'kek',
      fetchImpl: impl,
    })
    await sealer.wrap(new Uint8Array([1]))
    await sealer.wrap(new Uint8Array([2]))
    await sealer.unwrap(new Uint8Array([3]))
    expect(calls.filter((c) => c.url.includes('/oauth2/v2.0/token')).length).toBe(1)
  })

  it('throws on missing required config', () => {
    expect(
      () =>
        new AzureKeyVaultSealer({
          tenantId: '',
          clientId: 'c',
          clientSecret: 's',
          vaultUrl: 'https://v.vault.azure.net/',
          keyName: 'kek',
        }),
    ).toThrow(/missing config "tenantId"/)
  })
})
