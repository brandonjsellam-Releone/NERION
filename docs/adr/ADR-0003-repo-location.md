# ADR-0003: Repository location (Windows MAX_PATH)

- **Status:** Accepted (P0)
- **Date:** 2026-06-17

## Context

The session working directory is ~230 characters deep
(`…\local-agent-mode-sessions\…\outputs`). `git init` there failed with
`Filename too long`, and `npm`'s nested `node_modules` paths would exceed the
Windows 260-char `MAX_PATH` limit, breaking the build.

## Decision

Initialize the repository at a short root: **`C:\Users\User\polarseek`** (24
chars), leaving ample headroom for `.git/objects/...` and `node_modules/...`.
Enable `git config --global core.longpaths true` as belt-and-suspenders, and
enforce LF line endings via `.gitattributes` for reproducible builds.

## Consequences

- The repo is **not** under the session `outputs/` directory. The pre-existing
  PolarSeek analysis artifacts (report, one-pager, the SIGA source) remain in
  `outputs/`; the code lives at `C:\Users\User\polarseek`.
- A pointer note can be dropped in `outputs/` and the repo can be zipped into
  `outputs/` on request for hand-off.
- On a non-Windows or properly long-path-enabled host, the repo can live
  anywhere; nothing in the build depends on this path.
