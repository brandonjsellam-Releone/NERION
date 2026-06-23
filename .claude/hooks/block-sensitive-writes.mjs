// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// PreToolUse hook — Nerion credential + frozen-asset guard (Node.js ≥20)
//
// Blocks:
//   1. Writes/Edits to credential/key files (.env, *.key, *.pem, *.p12, *.pfx)
//   2. Writes to frozen conformance vectors (conformance/vectors/)
//   3. Reads of .env files and SSH keys (Law 18)
//   4. Force-push or direct push to main
//   5. KAT regeneration commands
//   6. rm -rf without human approval
//
// Exit 2 = BLOCK. Exit 0 = allow.

import { readFileSync } from 'node:fs'
import { execSync } from 'node:child_process'

function block(reason) {
  process.stderr.write(`[nerion-hook BLOCKED] ${reason}\n`)
  process.exit(2)
}

let input
try {
  const raw = readFileSync('/dev/stdin', 'utf8').trim()
  input = JSON.parse(raw)
} catch {
  // Cannot parse → allow (fail open on hook parse errors only)
  process.exit(0)
}

const toolName = input?.tool_name ?? ''
const toolInput = input?.tool_input ?? {}

// ─────────────────────────────────────────────────────────────────────────────
// Write / Edit — check file_path
// ─────────────────────────────────────────────────────────────────────────────
if (toolName === 'Write' || toolName === 'Edit') {
  const filePath = String(toolInput.file_path ?? '').replace(/\\/g, '/')

  const credentialPattern = /(\.(env)([^/]*)?$|\.key$|\.pem$|\.p12$|\.pfx$|\.crt$|\.jks$)/i
  if (credentialPattern.test(filePath)) {
    block(
      `credential/key write to '${filePath}'.\n` +
      `Law 18: Never write .env, *.key, *.pem, *.p12 without explicit per-session human approval.`
    )
  }

  if (/conformance\/vectors\//.test(filePath)) {
    block(
      `write to frozen conformance vector '${filePath}'.\n` +
      `KAT regeneration requires a Track-B ADR + full council sign-off + deliberate human approval.`
    )
  }

  if (/\.ssh\/|ssh_|id_rsa|id_ed25519|authorized_keys/.test(filePath)) {
    block(`SSH file write to '${filePath}'. Law 18: Never touch ~/.ssh/.`)
  }

  // Block re-introducing the redacted Azure identifiers
  const content = String(toolInput.content ?? toolInput.new_string ?? '')
  const azurePattern = /polarseek-kv-releone|polarseek-kms/
  if (azurePattern.test(content)) {
    block(
      `Azure identifier detected in write content.\n` +
      `Redacted vault/app names (polarseek-kv-releone, polarseek-kms) must never be committed.`
    )
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Read — block .env and SSH reads (Law 18)
// ─────────────────────────────────────────────────────────────────────────────
if (toolName === 'Read') {
  const filePath = String(toolInput.file_path ?? '').replace(/\\/g, '/')

  if (/\.(env)([^/]*)?$/i.test(filePath)) {
    block(
      `Read of '${filePath}' requires explicit per-session human approval.\n` +
      `Law 18: .env files contain API keys. Ask the user before reading.`
    )
  }

  if (/\.ssh\/|id_rsa|id_ed25519/.test(filePath)) {
    block(`SSH key read blocked. Law 18.`)
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bash — block dangerous commands
// ─────────────────────────────────────────────────────────────────────────────
if (toolName === 'Bash') {
  const cmd = String(toolInput.command ?? '')

  if (/git\s+push.*(--force|-f\b)/.test(cmd)) {
    block(`force-push detected: '${cmd.slice(0, 120)}'.\nForce-push requires explicit human approval.`)
  }

  if (/git\s+push\s+(origin\s+)?main\b/.test(cmd)) {
    block(
      `direct push to main: '${cmd.slice(0, 120)}'.\n` +
      `Team engine branches must be branch-only. A human merges to main.`
    )
  }

  if (/npm\s+run\s+kat|node\s+tools\/gen-kat/.test(cmd)) {
    block(
      `KAT regeneration command blocked: '${cmd.slice(0, 80)}'.\n` +
      `Requires Track-B ADR + council sign-off + deliberate human approval.`
    )
  }

  if (/\brm\s+-rf\b/.test(cmd)) {
    block(`rm -rf blocked. Destructive — requires explicit human approval.`)
  }

  if (/\bsource\s+\.env\b|cat\s+\.env|<\s*\.env/.test(cmd)) {
    block(`Bash access to .env blocked. Law 18: requires explicit per-session human approval.`)
  }

  // Block re-introducing redacted Azure identifiers in Bash output
  if (/polarseek-kv-releone|polarseek-kms/.test(cmd)) {
    block(`Redacted Azure identifier in Bash command. These must never appear in committed scripts.`)
  }
}

// Allow
process.exit(0)
