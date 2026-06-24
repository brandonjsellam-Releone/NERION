<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Rust Supply Chain Security

## cargo-audit
Run: cd rust && cargo audit
Checks all Rust dependencies against the RustSec advisory database.
This is non-blocking in CI (reports only).

## RustSec Advisory Database
Dependencies are checked weekly by Dependabot (see .github/dependabot.yml).
Security advisories appear as PRs within 24h of publication.

## Dependency Philosophy
- Prefer widely-audited crates (aes-gcm, hmac, sha3 from RustCrypto)
- Pin patch versions in Cargo.toml for reproducibility
- All direct dependencies carry permissive licenses (see .cargo/audit.toml)

## Known RustCrypto Audits
- aes-gcm: NCC Group audit 2022
- hmac/sha3: Formally verified properties; no standalone audit
- pqcrypto-* (if used): NIST reference implementation
