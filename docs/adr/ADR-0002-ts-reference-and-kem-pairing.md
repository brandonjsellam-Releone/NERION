# ADR-0002: TypeScript reference implementation & hybrid-KEM pairing

- **Status:** Accepted (P0)
- **Date:** 2026-06-17

## Context

The build spec mandates **Rust** for `crypto/`, `kernel/`, `translog/`,
`attest/` (memory safety, constant-time, performance). The P0 build environment
(Windows) has **git, Node 24/npm 11, Python 3.14, OpenSSL** but **no Rust/Go
toolchain**. The spec also forbids security theater: we must not present
non-compiling Rust as if it were real, tested code.

A second decision: the spec asks for KEM "hybrid X25519 + ML-KEM-1024", but the
audited library exposes X25519 paired with ML-KEM-768 (X-Wing) and ML-KEM-1024
paired with ECDH P-384 — and X25519+ML-KEM-1024 is a security-level mismatch.

## Decision

1. **P0 reference crypto is implemented in TypeScript** over the audited,
   pure-JS `@noble/post-quantum` (ML-KEM-1024, ML-DSA-87, SLH-DSA) +
   `@noble/curves` (X25519, P-384) + `@noble/ciphers` (AES-GCM) +
   `@noble/hashes` (SHA-384, SHA3/SHAKE, HMAC) + `cbor2` (deterministic CBOR).
   - TypeScript is itself a mandated SDK language, so this is on-roadmap, not a
     detour. It compiles and tests **green** today (51 tests passing).
   - The TS module defines the **canonical SuiteID contract** (interfaces in
     `crypto/src/types.ts`). The Rust hot-path implementation, when a toolchain
     is provisioned, MUST conform to the same SuiteID/envelope wire contract and
     pass the same `conformance/` vectors (differential testing).
2. **Hybrid KEM pairing by tier** (see ADR-0001): PS-1 = X-Wing
   (X25519+ML-KEM-768, IETF `draft-connolly-cfrg-xwing-kem`); PS-5 =
   ML-KEM-1024 + ECDH P-384 (CNSA-2.0-aligned Cat-5). We deviate from the literal
   "X25519+ML-KEM-1024" because it mismatches security levels; we record the
   deviation here per the spec's "choose the most secure, standards-aligned
   option and record it as an ADR" rule. Both use vetted library combiners.

## Consequences

- **Verifiable now:** `npm run gate` (format + typecheck + tests) is green; KAT
  vectors are committed and reproducible.
- **Rust is deferred, not abandoned.** Provisioning `rustup` and porting
  `crypto/`+`kernel/` to Rust behind the same SuiteID contract is the first item
  in [../STATUS.md](../STATUS.md) "next actions". Until then, the hot-path
  performance claims (<1 ms p50) are **targets**, not measured results.
- HQC and Falcon are honest stubs (`NotImplementedError`) because `@noble` does
  not provide them.
