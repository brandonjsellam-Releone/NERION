// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Environment loading for OPS integrations (NOT the protocol core).
 *
 * Loads a `.env` file into `process.env` using Node's built-in parser (no
 * dependency) and exposes small typed accessors. PolarSeek's crypto/kernel/
 * ledger read NO env vars; this is only for deployment, KMS/HSM, TEE, and media
 * integrations. Secrets live in `.env` (gitignored) — never committed.
 */

import { existsSync } from 'node:fs'

export class MissingEnvError extends Error {
  constructor(name: string) {
    super(`required environment variable "${name}" is not set`)
    this.name = 'MissingEnvError'
  }
}

/**
 * Load `.env` (default path) into process.env if present. Uses
 * `process.loadEnvFile` (Node ≥ 20.12 / 21.7 / 22+). Returns true if a file was
 * loaded. No-op (returns false) if the file is absent or the runtime lacks the
 * built-in loader (in which case start the process with `node --env-file=.env`).
 */
export function loadEnv(path = '.env'): boolean {
  if (!existsSync(path)) return false
  const p = process as unknown as { loadEnvFile?: (path: string) => void }
  if (typeof p.loadEnvFile === 'function') {
    p.loadEnvFile(path)
    return true
  }
  return false
}

/** Read an env var, returning `fallback` when unset or empty. */
export function getEnv(name: string, fallback?: string): string | undefined {
  const v = process.env[name]
  return v !== undefined && v !== '' ? v : fallback
}

/** Read a required env var; throws {@link MissingEnvError} when unset/empty. */
export function requireEnv(name: string): string {
  const v = process.env[name]
  if (v === undefined || v === '') throw new MissingEnvError(name)
  return v
}

/** True iff an env var is set to a non-empty value. */
export function hasEnv(name: string): boolean {
  const v = process.env[name]
  return v !== undefined && v !== ''
}
