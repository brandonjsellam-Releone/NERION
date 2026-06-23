---
name: nerion-apex-commit
description: >
  Nerion apex commit workflow. Runs the full gate, checks for secrets,
  verifies conformance, runs REUSE lint, then commits with proper
  TRELYAN/Opus-4.8 trailer and pushes to the designated branch.
  Never pushes to main from team engines.
---

# /nerion-apex-commit

Apex-grade commit workflow for the Nerion protocol. Runs every check before
touching git. Call this instead of a raw `git commit` after any change.

## Usage

```
/nerion-apex-commit [--branch <name>] [--message "<msg>"] [--main]
```

- `--branch`: push to this branch (default: current branch)
- `--message`: commit message body (default: prompted from staged diff)
- `--main`: only allowed for council-reviewed solo fixes in the main loop; team engines must NEVER pass this flag

---

## STEP 1 — Pre-flight: check for secrets

Scan staged files for credential patterns before running any tests:

```bash
git diff --cached --name-only | xargs -I{} grep -l \
  -E '(AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{40,}|nvapi-[a-zA-Z0-9_-]{40,}|moonshot-[a-zA-Z0-9_-]{20,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})' \
  {} 2>/dev/null || true
```

If any matches → **ABORT immediately**. Un-stage the file, redact the secret, re-stage.

Also verify the frozen KATs are NOT staged:
```bash
git diff --cached --name-only | grep 'conformance/vectors/' && echo "FROZEN KAT STAGED" && exit 1 || true
```

---

## STEP 2 — Gate

```bash
cd C:/Users/User/polarseek
npm run gate
```

Gate = lint:cleanroom + format:check + typecheck + vitest (462 tests).

If gate fails → fix ALL failures before proceeding. Do NOT skip or `--no-verify`.

---

## STEP 3 — Conformance

```bash
npm run build && npm run conformance
```

Must show `23/23` passing. If conformance drops → investigate immediately;
do NOT commit.

---

## STEP 4 — Rust check (if rust/ changed)

```bash
# Only if git diff --cached --name-only | grep -q '^rust/'
cd C:/Users/User/polarseek/rust
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

---

## STEP 5 — REUSE lint

```bash
~/.local/bin/reuse lint
```

Must show `188/188` (or more if new files added). If it fails:
- New `.ts` files missing SPDX → add the header block:
  ```
  // SPDX-FileCopyrightText: 2026 TRELYAN
  //
  // SPDX-License-Identifier: Apache-2.0
  ```
- New `.md` / config files → add `<!--` comment or equivalent + update `REUSE.toml`.

---

## STEP 6 — Build commit message

The commit message must:
1. Use imperative mood, one-line subject (≤72 chars)
2. Body: what changed and why (not "what the code does")
3. End with the council trailer if council-reviewed
4. Always end with:
   ```
   Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
   ```

Example:
```
fix: enforce audience binding in HKDF permit-key derivation

Permit keys were derived from a shared HKDF root without audience
domain-separation, allowing cross-audience key reuse. Now each
audience gets a salted sub-key via HKDF-Expand with label
"nerion-permit/<audience>".

Fixes: PERMIT-001 (ADR-0015)
Council: APPROVED 9/11 (Nemotron + Kimi K2 via direct API)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

---

## STEP 7 — Commit

```bash
git commit -m "$(cat <<'EOF'
<subject line>

<body>

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## STEP 8 — Push

**Team engine (branch-only):**
```bash
git push -u origin <branch>
```

**Main-loop solo council-reviewed fix (only with --main flag):**
```bash
git push origin main
```

NEVER run `git push origin main` from a team engine scheduled task.
NEVER use `--force` or `--force-with-lease` without explicit human approval.

---

## STEP 9 — Sprint log

Append one line to `docs/APEX_SPRINT_LOG.md`:
```
YYYY-MM-DD HH:MM | <branch> | <item summary> | gate: PASS | conformance: 23/23 | council: N/11
```

---

## STEP 10 — Report

Output:
```
✓ Gate: PASS (462 tests)
✓ Conformance: 23/23
✓ REUSE: N/N
✓ No secrets found
✓ Committed: <sha>
✓ Pushed: origin/<branch>
```

Or on any failure: `✗ BLOCKED — <reason>`. Do not partially complete the workflow.
