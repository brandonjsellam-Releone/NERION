<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0028: hybrid-KEM sealing — KDF context-binding requirement (R2)

**Status:** Accepted (forward requirement; pre-implementation — no KEM-sealing/confidentiality path
exists in the codebase yet). Pins the rule so the future path cannot introduce the gap.

## Context

Nerion registers **only hybrid KEMs** (`crypto/src/kem.ts`): X-Wing (X25519 + ML-KEM-768, general
tier) and ML-KEM-1024 + P-384 (CNSA-2.0 Cat-5 tier), both from `@noble/post-quantum/hybrid`. The
**combiner** — the step that mixes the two shared secrets together with the classical ciphertext and
public key into one shared secret — is the audited IETF X-Wing / noble construction. Nerion does **not**
roll its own combiner (build-spec guardrail), and its binding properties are regression-tested in
`crypto/test/kem.test.ts` (a tampered ciphertext yields a different secret via ML-KEM implicit
rejection; a wrong key cannot decapsulate).

The auditor-dossier residual **R2** is about the layer **above** the combiner: an unknown-key-share or
cross-suite / downgrade attack is possible if the KEM shared secret is later expanded into working keys
**without binding the protocol context**. Today the KEM is registered + conformance-round-tripped +
binding-tested but is **not yet wired into any seal/open path** (the only `encapsulate` callers are
`kem.ts` and the C-check). So there is no live binding *bug* — but the requirement must be fixed now, in
writing, before that path is built.

## Decision (requirement for ANY future KEM-sealing path)

1. The raw KEM `sharedSecret` **MUST NOT** be used directly as an encryption/MAC key.
2. It **MUST** be run through the registered KDF (**HKDF-SHA-384**) whose `info` is **canonical CBOR**
   (length-prefixed, key-order-independent — `encodeCanonical`) binding **all** of:
   - the **SuiteID** (so a key minted under one suite is unusable under another → no downgrade reuse),
   - the **KEM-id** (X-Wing vs ML-KEM-1024+P-384),
   - the **full ciphertext**,
   - **sender and recipient** public-key identifiers (audience binding → no unknown-key-share),
   - a fixed **protocol label + version** string (domain-separation from the permit-token / other
     HKDF uses already in `crypto/src/symmetric.ts` / `envelope.ts`).
3. The same `info` MUST be reconstructed on the open side, so a mismatch in any bound field yields a
   different key and fails closed.

## Consequences

- The requirement is pinned **before** the code exists, so the Engineering team's eventual sealing path
  can be checked against it (and a conformance/negative KAT added then: wrong-suite / wrong-recipient /
  swapped-ciphertext `info` ⇒ distinct key).
- **No code or KAT change now** — there is no sealing path to alter; this is a design record.
- The combiner *internals* (does the IETF/noble construction bind both shared secrets, both public
  keys, and both ciphertexts exactly as the X-Wing draft specifies) remain an **upstream
  cryptographer-review** item — out of Nerion's scope, tracked under R2.
