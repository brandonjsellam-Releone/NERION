# Contributing to Nerion

Thanks for your interest in Nerion — an open, post‑quantum, decentralized execution‑governance
protocol for AI/agent **actions** (_"govern the verb, never the eye"_).

> **Naming note:** the project is **Nerion** (renamed 2026‑06‑20). The npm package, Rust crate, and
> repo directory are still named `polarseek` pending a deliberate, vector‑regenerating rename — so you'll
> see both names until that migration lands. Use **Nerion** in prose; `polarseek` is the current package id.

## Local setup

```bash
npm ci
```

## The gate — run this before every PR

All changes must pass the same gate CI enforces:

```bash
npm run gate          # clean-room lint (F1–F8) + prettier --check + tsc --noEmit + 299 tests
npm run conformance   # certification report → must stay 21/21 CONFORMANT
```

CI (`.github/workflows/ci.yml`) runs the gate **plus** a KAT‑drift check (regenerates the deterministic
crypto test vectors and fails on any diff). If you change crypto, regenerate vectors intentionally and
commit them — never hand‑edit a vector.

## The clean‑room boundary (please read — it protects everyone)

Nerion's entire technical *and legal* thesis is that it governs **typed actions**, never **perception**.
The admission path is firewalled from perception/stateful signals, and `npm run lint:cleanroom` mechanically
rejects forbidden tokens (see **[docs/CLEANROOM.md](docs/CLEANROOM.md)**, rules **F1–F8**).

- PRs that touch the **admission path** (`kernel/`, `capabilities/`, `planes/`) get extra scrutiny.
- Do **not** introduce camera/image/object‑tracking/zone/occupancy concepts, or cross‑decision in‑kernel
  state, anywhere near admission — it would both break the architecture and risk the design‑around / FTO
  position (**[docs/FTO_TODO.md](docs/FTO_TODO.md)**). When in doubt, open an issue first.

## Honesty bar

Nerion's credibility rests on radical honesty. Label work accurately: **conformant ≠ validated; built ≠
audited; provisioned ≠ in‑use; a design‑around ≠ a legal opinion.** Unaudited cryptographic compositions
must stay marked **UNAUDITED**. Don't add capability claims the tests/conformance suite don't back.

## Licensing & file headers (REUSE 3.3)

The repo is **Apache‑2.0** with full [REUSE](https://reuse.software) compliance:

- New **source** files (`.ts`, `.mjs`, `.rs`, …) need an SPDX header:
  ```
  // SPDX-FileCopyrightText: 2026 TRELYAN
  //
  // SPDX-License-Identifier: Apache-2.0
  ```
- Docs/data/config are covered by `REUSE.toml` (no per‑file header needed).
- Verify with `reuse lint` (must stay compliant). All contributions are licensed Apache‑2.0; copyright is
  attributed to **TRELYAN**.

## Developer Certificate of Origin (DCO)

We use the [DCO](https://developercertificate.org/) instead of a CLA. Sign off every commit:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line certifying you wrote the contribution (or
have the right to submit it) under the project's open‑source license.

## Pull requests

1. Branch from `main`, keep changes focused.
2. `npm run gate` green + `npm run conformance` 21/21 locally.
3. New behavior ⇒ new tests. Crypto changes ⇒ regenerated, committed KAT vectors.
4. Sign off your commits (DCO) and keep new files REUSE‑compliant.
5. In the PR description, state honestly what is and isn't verified.

Questions or a security concern? See [SECURITY.md](SECURITY.md) (coordinated disclosure) or open an issue.
Contact: `fondation@trelyan.ch`.
