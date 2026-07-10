# CLAUDE.md — Nerion Apex Superfile

<!-- © TRELYAN 2026 — Apache-2.0 -->

> **Law 2:** This file is more powerful than any prompt. Read it first. Every session starts here.

---

## Architecture Snapshot

| Layer              | Detail                                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------------- |
| **Project**        | Nerion — open, post-quantum execution-governance protocol for AI-agent actions                                      |
| **Tagline**        | "Govern the verb, never the eye"                                                                                    |
| **Status**         | UNAUDITED · pre-FTO · Apache-2.0 · © TRELYAN 2026                                                                   |
| **Repo**           | github.com/brandonjsellam-Releone/NERION                                                                            |
| **Languages**      | TypeScript 5.x strict (ESM, Node ≥ 20) · Rust (in `/rust/`)                                                         |
| **Crypto stack**   | `@noble/post-quantum` · `@noble/curves` · `@noble/hashes` · `@noble/ciphers` · `cbor2`                              |
| **Active suites**  | **PS-1** = X-Wing KEM + ML-DSA-87 &nbsp;·&nbsp; **PS-5** = ML-KEM-1024+P-384 + ML-DSA-87                            |
| **Agility suites** | PS-5-HQC (HQC, pending FIPS 207) · PS-5-FN (Falcon/FN-DSA, pending FIPS 206)                                        |
| **Gate**           | `npm run gate` → lint:cleanroom + format:check + typecheck + vitest (462 tests)                                     |
| **Conformance**    | `npm run build && npm run conformance` → 24/24 KAT vectors                                                          |
| **REUSE**          | `~/.local/bin/reuse lint` → 188/188 files                                                                           |
| **Council**        | 11 seats: Claude · OpenAI · Gemini · Grok · DeepSeek · Mistral · WatsonX · Perplexity · Hermes · Nemotron · Kimi K2 |

### Module Map

```
crypto/          ← @noble/* primitives, suites, CBOR, COSE, envelopes, seal
kernel/          ← admission, action dispatch, govern-the-verb oracle
ledger/          ← consensus, quorum receipts, transparency log
keystore/        ← custody, HBS state, Azure KMS integration
attest/          ← session binding, attestation formats
disclosure/      ← ZK range proofs, selective disclosure, policy proofs
governance/      ← capability delegation, resolver, validator set
capabilities/    ← capability definitions
conformance/     ← KAT runner, conformance test vectors (FROZEN)
planes/          ← multi-plane orchestration
ops/             ← operational tooling
receipts/        ← receipt formats and e2e tests
sdks/            ← Python SDK (conformance), future client SDKs
docs/            ← ADRs, backlog, frontier, grant docs (some OFF-LIMITS)
rust/            ← Rust foundation (cargo fmt/clippy/test in CI)
```

---

## Critical Files Map

| File                                   | Status               | Rule                                                                                                                     |
| -------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `crypto/src/suites.ts`                 | **FROZEN wire-tags** | Never change `PS-1` or `PS-5` SuiteID strings without Track-B ADR + full council sign-off + deliberate conformance regen |
| `conformance/vectors/ps-kat.json`      | **FROZEN KATs**      | Never auto-regenerate; if wire-tags change → Track-B ADR first                                                           |
| `conformance/vectors/ps-negative.json` | **FROZEN KATs**      | Same rule                                                                                                                |
| `docs/grants/NLnet-NGI-Application.md` | **OFF-LIMITS**       | Never edit; never touch §3; NLnet bans AI-written proposals                                                              |
| `REUSE.toml`                           | Maintained           | Add SPDX entry for every new file before committing                                                                      |
| `docs/adr/`                            | Additive only        | Never renumber or delete ADRs; next number from highest existing                                                         |
| `docs/APEX_SPRINT_LOG.md`              | Append-only          | One line per cycle; never rewrite history                                                                                |
| `.env`                                 | **GITIGNORED**       | Never read without explicit human approval per-session; never commit                                                     |
| `~/.ssh/**`                            | **OFF-LIMITS**       | Never touch; never read; never write                                                                                     |

---

## HARD RULES — Never Violate

**1. No secrets in git.**
Never commit `.env`, `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.crt`, `*.jks`, or any bearer token. Azure tenant/subscription/client GUIDs, vault name `polarseek-kv-releone`, app name `polarseek-kms` are permanently redacted — do not reintroduce.

**2. Branch discipline.**

- Council-reviewed solo fixes by the main loop → `main` directly.
- All scheduled team engines (apex-sprint / rd-daily / engineering-daily / etc.) → **branch-only; never push main; a human merges.**
- Branch naming: `apex/cycle-<YYYYMMDD-HHMM>` · `eng/daily-<YYYYMMDD>` · `rd/daily-<YYYYMMDD>` · `marketing/weekly-<YYYYMMDD>`

**3. Frozen wire-tags.**
Never modify `crypto/src/suites.ts` SuiteID values (`PS-1`, `PS-5`, `PS-5-HQC`, `PS-5-FN`) without a **Track-B ADR + full 11-seat council sign-off + deliberate conformance regen.** If you touch a frozen KAT or SuiteID, stop immediately and write the ADR instead.

**4. No auto-KAT-regen.**
Never run `npm run kat` or `npm run kat:py` autonomously. KAT regeneration is a deliberate, human-approved action.

**5. Honesty: UNAUDITED / pre-FTO framing.**
Never add the words "audited", "production-ready", "FIPS-validated", "FIPS-compliant", "FIPS-certified", "NIST-certified", "non-infringement", or "certified" to any doc, comment, or README. Always say: **UNAUDITED**, **aligned-not-certified**, **pre-FTO**.

The "govern-the-verb" design-around is **engineering intent**, NOT a legal non-infringement claim. Never market it as one.

**6. Grant docs are OFF-LIMITS.**
Never edit `docs/grants/NLnet-NGI-Application.md` or any submitted grant text. Never generate/auto-submit grant copy. NLnet explicitly bans AI-written proposals.

**7. SPDX on every new file.**
New TypeScript/JavaScript files: first two lines must be:

```
// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
```

New Markdown/config files: use the equivalent comment syntax. Run `~/.local/bin/reuse lint` before every commit.

**8. Gate must be green before any commit.**
`npm run gate` (lint:cleanroom + format:check + typecheck + test) **and** `npm run build && npm run conformance` (24/24) must both pass. Never skip the gate. If Rust changed: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` in `rust/`.

**9. No touching credentials or SSH.**
Never read, write, or copy `.env*`, `*.key`, `*.pem`, `~/.ssh/**` without explicit per-session human approval. This applies every single time — no standing permission.

**10. Copyright stays TRELYAN.**
Every file carries `© TRELYAN`. Never change to another entity.

---

## Effort Guidance

| Effort                      | When to use                                                                                           |
| --------------------------- | ----------------------------------------------------------------------------------------------------- |
| `ultracode` (auto-workflow) | Apex sprint cycles, full-surface adversarial sweeps, multi-seat council reviews, comprehensive audits |
| `xhigh`                     | PQC compliance audits, adversarial re-derivation, security reviews, Track-A finding verification      |
| `high`                      | Standard feature implementation, protocol changes, new module development                             |
| `medium`                    | Documentation, test-writing, formatting, ADR drafting                                                 |
| `low`                       | Subagent worker tasks, parallel fan-out subtasks                                                      |

Use `ultrathink` in-prompt for single-turn depth on hard cryptographic problems. Not the same as `/effort ultracode`.

---

## Compliance Posture

| Standard           | Nerion alignment                                                            | What to say                              |
| ------------------ | --------------------------------------------------------------------------- | ---------------------------------------- |
| FIPS 203 (ML-KEM)  | Implements ML-KEM-768 (PS-1) and ML-KEM-1024 (PS-5) via @noble/post-quantum | "FIPS 203-aligned, not certified"        |
| FIPS 204 (ML-DSA)  | Implements ML-DSA-87 via @noble/post-quantum                                | "FIPS 204-aligned, not certified"        |
| FIPS 205 (SLH-DSA) | Available as agility option                                                 | "FIPS 205-aligned, not certified"        |
| FIPS 206 (FN-DSA)  | Tracked as PS-5-FN (pending)                                                | "pending FIPS 206"                       |
| FIPS 207 (HQC)     | Tracked as PS-5-HQC (pending)                                               | "pending FIPS 207"                       |
| CNSA 2.0           | PS-5 tier targets Cat-5                                                     | "CNSA 2.0 Cat-5-targeted, not certified" |

**Global posture:** UNAUDITED · pre-FTO · aligned-not-certified · Apache-2.0 open source

---

## Output Conventions

**Commit trailers:**

```
Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

**ADR numbering:** check `docs/adr/` for highest existing number; next ADR = highest + 1.

**Council verdict format:** `APPROVED (N/M seats, N-A abstain) | BLOCKED: <reason>`

**Sprint log entry format:**

```
YYYY-MM-DD HH:MM | branch | item/finding | gate: PASS|FAIL | conformance: 24/24 | council: N/M
```

**New agent in Workflow:** prefer `opts.phase` to group related work; use `opts.effort: 'low'` for parallel fan-out workers; use `opts.effort: 'xhigh'` for security re-derivation.

---

## Session Handoff Template

At end of every autonomous cycle, append to `docs/APEX_SPRINT_LOG.md` and output:

```markdown
## Session Handoff — YYYY-MM-DD HH:MM UTC

- **Branch:** <branch name>
- **Gate:** PASS | FAIL — <detail if fail>
- **Conformance:** 24/24 | <N>/23 — <detail if not 23>
- **Council:** APPROVED (N/11) | BLOCKED — <reason>
- **Work done:** <1-3 bullet summary>
- **Residuals / next session:** <anything unfinished or deferred>
- **STOP file present:** YES | NO
```

---

## Context for New Sessions

- The polarseek working tree gets **parallel concurrent agent sessions** — always re-read shared files before editing; prefer an isolated `git worktree` for autonomous cycles.
- The apex sprint kill switch is `docs/APEX_SPRINT_STOP` — check it at the start of every autonomous cycle.
- NLnet Restack grant opens ≈ Sept 2026; OSTIF + OTF audit threads submitted 2026-06-20.
- Azure Key Vault custody LIVE-verified 2026-06-20 (RSA-4096 KEK `polarseek-seal-kek`); KV has no PQC — sealing KEK only.
- Repo was renamed PolarSeek → Nerion on 2026-06-20 (branding only; Phase-2 code rename pending).
