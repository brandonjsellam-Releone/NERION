<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion — Security Posture

> **Honest framing (read first).** Nerion is **pre‑audit and pre‑FTO**. The cryptographic
> *primitives* are upstream‑audited (`@noble`), but every novel composition layered on top is
> **UNAUDITED**. Nothing here is a non‑infringement, "audited," "production‑ready," or FIPS claim.
> Treat all security properties as **claims, not established facts**, until an external audit report
> and a patent‑counsel FTO opinion exist. See [AUDIT_PACKAGE.md](./AUDIT_PACKAGE.md) (auditor scope)
> and [FTO_TODO.md](./FTO_TODO.md) (freedom‑to‑operate).

This document records the project's **operational security posture** — how secrets are handled, how
the public repository is kept clean, and the one resolved repository‑hygiene finding to date. For the
**vulnerability‑reporting policy** see the root [SECURITY.md](../SECURITY.md); for the **code‑level
findings index** (the Team Apex internal audit) see [SECURITY_FINDINGS.md](./SECURITY_FINDINGS.md).

## 1. Reporting a vulnerability

Report privately to **fondation@trelyan.ch** with subject `SECURITY: Nerion`. Please **do not** open a
public issue, PR, or discussion for security matters. The full policy — coordinated‑disclosure window,
scope, and supported versions — is in the root [SECURITY.md](../SECURITY.md).

## 2. Secret handling

- **The protocol core reads no environment variables.** Keys are passed explicitly or come from a
  keystore / KMS provider. Environment variables exist only for opt‑in OPS integrations (deployment,
  cloud KMS/HSM custody, TEE attestation, transparency‑log hosting, media generation).
- **No real secret has ever been committed.** The runtime secrets file `.env` is **gitignored**
  (`.gitignore`: `.env` and `.env.*`, with `!.env.example` re‑included). Only the blank template
  **`.env.example`** is tracked — every secret‑bearing field in it (tokens, client secrets, API keys)
  is empty by design, and the template header states "NEVER commit real secrets."
- Cloud‑KMS custody (Azure Key Vault, AWS KMS) seals the PQC seed at rest; the wrapping/seal key lives
  in the vault/HSM, never in the repository.

## 3. Resolved findings

### SEC‑HIST‑001 — Azure resource identifiers briefly in git history (RESOLVED)

**Class:** repository hygiene / metadata exposure. **Severity:** low (non‑secret identifiers only).
**Status:** RESOLVED — redacted at HEAD and **purged from history**.

**What happened.** An older commit briefly contained Azure **resource identifiers** — described here by
type only: the tenant ID, the subscription ID, and an application/client ID (all directory/resource
**GUIDs**), plus the Key Vault **URL**. These are non‑secret routing/addressing identifiers, not
credentials. **The Azure client secret was never committed and was never exposed** — that field has
always been blank in the tracked `.env.example`, and the real value lives only in the gitignored
`.env`.

**Why it still mattered.** Even though these identifiers are non‑secret, leaving them in a public
history is unnecessary metadata exposure (it reveals tenant/subscription/vault topology). The
remediation removed them entirely rather than relying on their non‑secret nature.

**Remediation.**

1. Redacted the identifiers at **HEAD** (current tree carries none).
2. **Purged them from the entire history** with `git filter-repo`, followed by a **force‑push** to the
   public remote so no historical revision retains them.

**Verification.** Re‑run over the rewritten repository:

```sh
git -C "$WT" log --all -p \
  | grep -E "<tenant-guid>|<subscription-guid>|<client-guid>|<vault-name>|<kms-key-name>" \
  | wc -l
```

(The actual GUIDs and vault/key names are intentionally **not reproduced here** — they are matched in
the real command by their literal values, omitted from this document by design.)

**Result: `0` — 0 occurrences in current history.** No historical revision of the purged repository
contains the tenant, subscription, or client GUID, the vault URL/name, or the KMS key name. The client
secret was never present to begin with.

> Note on history rewrites: a `filter-repo` + force‑push rewrites commit hashes. Any pre‑existing clone
> or fork taken before the purge could still hold the old objects locally; the canonical public remote
> does not. Because the purged values are non‑secret identifiers (and the secret was never exposed),
> no key rotation was required.

## 4. Audit & FTO status

Nerion is **UNAUDITED** and **pre‑FTO**.

- **Cryptographic / protocol audit:** scope is auditor‑ready but no external report exists yet. See
  [AUDIT_PACKAGE.md](./AUDIT_PACKAGE.md) and the internal‑lead findings index
  [SECURITY_FINDINGS.md](./SECURITY_FINDINGS.md). Passing the bundled test vectors demonstrates **KAT
  conformance only** — not overall protocol security or production‑readiness.
- **Freedom‑to‑operate:** the design‑around choices are **engineering intent, not a legal
  non‑infringement claim**. No public non‑infringement or "clear of patents" statement may be made
  until a written FTO opinion from qualified patent counsel is on file. See
  [FTO_TODO.md](./FTO_TODO.md).

Copyright 2026 TRELYAN — Apache‑2.0.
