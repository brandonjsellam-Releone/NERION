#!/usr/bin/env node

// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Live Azure Key Vault custody check — proves model-B PQC seed sealing works
 * against YOUR vault, using credentials read from `.env` (gitignored).
 *
 * It generates a random 32-byte seed, wraps it (RSA-OAEP-256) with the vault KEK,
 * unwraps it, and asserts a byte-identical round-trip. It NEVER prints the seed,
 * the wrapped blob's contents, or any secret — only the vault URL, the key name,
 * and the sealed byte length.
 *
 * Prereq: `npm run build` (uses dist/). Fill these in `.env`:
 *   AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
 *   AZURE_KEY_VAULT_URL, AZURE_KEY_VAULT_KEK_NAME
 * Run:  node tools/azure-custody-check.mjs
 */
import { randomBytes } from 'node:crypto'
import { azureSealerFromEnv } from '../dist/keystore/src/index.js'
import { loadEnv } from '../dist/ops/src/index.js'

loadEnv() // load .env if present (no-op otherwise)

const need = [
  'AZURE_TENANT_ID',
  'AZURE_CLIENT_ID',
  'AZURE_CLIENT_SECRET',
  'AZURE_KEY_VAULT_URL',
  'AZURE_KEY_VAULT_KEK_NAME',
]
const missing = need.filter((k) => !process.env[k])
if (missing.length > 0) {
  console.error('✗ Missing .env values:', missing.join(', '))
  console.error('  See docs/ENV-SOURCING.md. The KEK name is the RSA key inside the vault.')
  process.exit(2)
}

const sealer = azureSealerFromEnv(process.env)
const seed = new Uint8Array(randomBytes(32)) // a throwaway test seed, never logged

console.log(`Azure KV custody check → ${process.env.AZURE_KEY_VAULT_URL}`)
console.log(`  KEK key: ${process.env.AZURE_KEY_VAULT_KEK_NAME}  (RSA-OAEP-256 wrap of a PQC seed)`)

try {
  const wrapped = await sealer.wrap(seed)
  const unwrapped = await sealer.unwrap(wrapped)
  const ok = seed.length === unwrapped.length && seed.every((b, i) => b === unwrapped[i])
  if (ok) {
    console.log(`✔ wrap/unwrap round-trip OK (sealed ${wrapped.length} bytes).`)
    console.log('  Model-B custody is LIVE: the vault seals the PQC seed at rest; signing stays in PolarSeek.')
    process.exit(0)
  }
  console.error('✗ round-trip MISMATCH — the unwrapped seed did not equal the original.')
  process.exit(1)
} catch (e) {
  console.error(`✗ Azure call failed: ${(e instanceof Error ? e.message : String(e))}`)
  console.error('  Check: the KEK exists in the vault, the SP "redacted-app" has Key Vault Crypto User, and outbound network reaches Azure.')
  process.exit(1)
}
