# Security Policy

## Status (read first)

Nerion is **pre‑audit**. The cryptographic *primitives* it builds on are upstream‑audited
(`@noble`), but the **novel compositions layered on top are UNAUDITED** — in particular the
zero‑knowledge layer in `disclosure/` (`zkrange.ts`, `policyproof.ts`, `commitbind.ts`). Treat all
security properties as **claims, not established facts**, until an external audit report exists. Do
not rely on Nerion for production security yet.

## Reporting a vulnerability

**Please report privately — do not open a public issue, PR, or discussion for security matters.**

- Email: **fondation@trelyan.ch** with subject `SECURITY: Nerion`.
- Include: affected file(s)/commit, a description, and (if possible) a reproduction or PoC.
- For sensitive reports, request our PGP key in your first message and we'll provide one before you
  send details.

We aim to acknowledge within **5 business days**.

## Coordinated disclosure

We follow **coordinated disclosure with a 90‑day window** (extendable by mutual agreement for complex
fixes), consistent with common open‑source and auditor practice. We will work with you on a fix and a
public advisory, and we're glad to credit reporters who wish to be named.

There is **no paid bug bounty** at this stage (pre‑funding); we will recognize valid reports publicly
with thanks.

## Scope

In scope (most valuable):

- The **unaudited ZK layer**: range proof, hidden‑amount policy‑satisfaction proof, and the v:2
  commitment‑to‑intent binding (`disclosure/`).
- The **admission path** and clean‑room boundary (`kernel/`, `capabilities/`, `planes/`) — e.g. any
  way to make a denied action execute, replay a permit, or smuggle perception/stateful state into the
  kernel.
- Receipt / transparency‑log integrity, quorum‑receipt forgery, and key‑custody handling
  (`keystore/`).

Out of scope: vulnerabilities in upstream dependencies (report those upstream), and theoretical
quantum attacks on clearly‑labeled transitional/classical legs already disclosed in the CBOM.

## Supported versions

Pre‑1.0; only `main` is supported. There are no released versions yet.

Copyright 2026 TRELYAN — Apache‑2.0.
