#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 TRELYAN
#
# SPDX-License-Identifier: Apache-2.0
#
# PreToolUse hook — Nerion credential + frozen-asset guard
#
# Blocks:
#   1. Writes to credential/key files (.env, *.key, *.pem, *.p12, *.pfx, *.crt)
#   2. Writes to frozen conformance vectors (conformance/vectors/)
#   3. Reads of .env files (Law 18: requires explicit human approval per-session)
#   4. Force-push or push to main
#   5. KAT regeneration commands (npm run kat, node tools/gen-kat*)
#
# Exit 2 = BLOCK the tool call (Claude Code interprets this as BLOCK).
# Exit 0 = allow.

set -euo pipefail

# Read tool call JSON from stdin
INPUT="$(cat)"

TOOL_NAME="$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_name',''))" 2>/dev/null || true)"

# ─────────────────────────────────────────────────────────────────────────────
# Write / Edit tool — check file_path
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$TOOL_NAME" == "Write" || "$TOOL_NAME" == "Edit" ]]; then
  FILE_PATH="$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('file_path',''))" 2>/dev/null || true)"

  # Credential / key files
  if echo "$FILE_PATH" | grep -qiE '(\.env[^/]*$|\.key$|\.pem$|\.p12$|\.pfx$|\.crt$|\.jks$)'; then
    echo "BLOCKED by nerion hook: credential/key write to '$FILE_PATH'." >&2
    echo "Law 18: Never write .env, *.key, *.pem, *.p12 without explicit per-session human approval." >&2
    exit 2
  fi

  # Frozen conformance vectors
  if echo "$FILE_PATH" | grep -qE 'conformance/vectors/'; then
    echo "BLOCKED by nerion hook: write to frozen conformance vector '$FILE_PATH'." >&2
    echo "KAT regeneration requires a Track-B ADR + full council sign-off + deliberate human approval." >&2
    exit 2
  fi

  # SSH directory
  if echo "$FILE_PATH" | grep -qE '(\.ssh/|ssh_|id_rsa|id_ed25519|authorized_keys)'; then
    echo "BLOCKED by nerion hook: SSH file write to '$FILE_PATH'." >&2
    echo "Never touch ~/.ssh/ — Law 18." >&2
    exit 2
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Read tool — block .env reads (require explicit human approval per-session)
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$TOOL_NAME" == "Read" ]]; then
  FILE_PATH="$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('file_path',''))" 2>/dev/null || true)"

  if echo "$FILE_PATH" | grep -qiE '\.env[^/]*$'; then
    echo "BLOCKED by nerion hook: Read of '$FILE_PATH' requires explicit per-session human approval." >&2
    echo "Law 18: .env files contain API keys. Ask the user before reading." >&2
    exit 2
  fi

  if echo "$FILE_PATH" | grep -qE '(\.ssh/|id_rsa|id_ed25519)'; then
    echo "BLOCKED by nerion hook: SSH file read blocked." >&2
    exit 2
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Bash tool — block dangerous commands
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$TOOL_NAME" == "Bash" ]]; then
  CMD="$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" 2>/dev/null || true)"

  # Force-push
  if echo "$CMD" | grep -qE 'git\s+push.*(--force|-f)'; then
    echo "BLOCKED by nerion hook: force-push detected." >&2
    echo "Force-push can destroy history. Requires explicit human approval." >&2
    exit 2
  fi

  # Push to main directly
  if echo "$CMD" | grep -qE 'git\s+push\s+(origin\s+)?main'; then
    echo "BLOCKED by nerion hook: direct push to main." >&2
    echo "Team engine branches must be branch-only. A human merges to main." >&2
    exit 2
  fi

  # KAT regeneration
  if echo "$CMD" | grep -qE '(npm\s+run\s+kat|node\s+tools/gen-kat)'; then
    echo "BLOCKED by nerion hook: KAT regeneration command detected." >&2
    echo "KAT regen requires a Track-B ADR + council sign-off + deliberate human approval." >&2
    exit 2
  fi

  # rm -rf
  if echo "$CMD" | grep -qE 'rm\s+-rf'; then
    echo "BLOCKED by nerion hook: rm -rf is a destructive operation requiring human approval." >&2
    exit 2
  fi

  # Sourcing or cat-ing .env
  if echo "$CMD" | grep -qE '(source\s+\.env|cat\s+\.env|<\s*\.env|\.env\s+\|)'; then
    echo "BLOCKED by nerion hook: .env access via Bash requires explicit per-session human approval." >&2
    exit 2
  fi
fi

# Allow
exit 0
