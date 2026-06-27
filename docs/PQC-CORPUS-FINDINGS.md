<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# PQC / Security Corpus — Deep-Read Findings Index

> A 15-document post-quantum & security corpus was deep-read in 2026-06 to extract
> requirements implementable into Nerion. This index records the method, the
> corpus, what was implemented, and what is deferred — with citations.
>
> **Provenance honesty:** the four normative specs and the AI-governance set were
> read **page-by-page directly** (and their findings are implemented in this
> branch). The four large reference volumes were **machine-read by the apex team's
> reader agents** with a *targeted* scope (navigate by knowledge-area/chapter to
> the Nerion-relevant sections — reading ~1.5M words verbatim would be waste);
> 14/15 documents yielded 161 raw findings. The team's council-synthesis pass was
> interrupted by a transient provider rate-limit, so the large-volume findings
> below are summarized at takeaway level pending a clean synthesis run.

## Method

- Normative specs → full page-by-page read, every MUST/SHALL extracted, mapped to
  Nerion code, and locked with tests (`crypto/test/fips-conformance-negative.test.ts`)
  and `docs/FIPS-CONFORMANCE-MAP.md`.
- AI-governance docs → full read, mapped in `docs/AI-SECURITY-HARDENING-MAP.md`.
- Large reference volumes → targeted deep-read by knowledge area, takeaways below.
- Classification: **TEST** (conformance/negative test), **DOC** (mapping/threat/assurance),
  **TRACK-B** (protocol/KAT-affecting — council-gated, deferred), **CONTEXT** (rationale).

## Corpus

| Document | Size | Read depth | Role |
|---|---|---|---|
| NIST.FIPS.203 (ML-KEM) | ~18k w | full page-by-page | normative — KEM |
| NIST.FIPS.204 (ML-DSA) | ~23k w | full page-by-page | normative — signatures |
| NIST.FIPS.205 (SLH-DSA) | ~21k w | full page-by-page | normative — hash-based sigs |
| djb, *Introduction to PQC* | ~6k w | full | rationale — PQC taxonomy |
| Post-Quantum Cryptography: A Comprehensive Guide | ~17k w | full/targeted | migration & implementation |
| NIST.CSWP.29 | ~9k w | full | PQC migration / CSF |
| KNC NIST CSF Implementation Guide (sample) | ~4k w | full | CSF function mapping |
| SANS — Own AI Securely | ~7k w | full | AI governance (Govern-AI track) |
| Security for AI Blueprint (datacenter/cloud) | ~5k w | full | LLM attack surface / six-layer |
| Cybersecurity Handbook | ~15k w | targeted | key mgmt / crypto governance |
| 978-981-19-7644-5 (Springer) | ~61k w | targeted | lattice internals / impl security |
| 9789819612185 | ~217k w | targeted | PQC / consensus / formal methods |
| CyBOK v1.1.0 | ~512k w | targeted | authoritative threat taxonomy |
| SEv3 (Security Engineering) | ~553k w | targeted | protocols / crypto / supply chain |

## Implemented-now (this branch)

| ID | Item | Type | Source |
|---|---|---|---|
| F-1 | ML-KEM §7.2 wrong-length encapsulation-key rejection | TEST | FIPS 203 §7.2 |
| F-2 | ML-KEM §7.3 wrong-length ciphertext rejection (every Decaps) | TEST | FIPS 203 §7.3 |
| F-3 | ML-KEM §6.3 implicit-rejection: tampered ct ⇒ deterministic, same-length, ≠ honest secret | TEST | FIPS 203 §6.3 |
| F-4 | ML-DSA Verify rejects wrong-length σ | TEST | FIPS 204 inputs |
| F-5 | ML-DSA Verify rejects wrong-length pk | TEST | FIPS 204 inputs |
| F-6 | Verify rejects all-zero signature (incl. SLH-DSA) | TEST | FIPS 204/205 |
| F-7 | Full FIPS 203/204/205 ↔ Nerion conformance map + `@noble` delegation boundary | DOC | all three specs |
| F-8 | AI-security controls → Nerion govern-the-verb hardening map | DOC | SANS / AI Blueprint / CSF / AI RMF |

All TEST items pass; full gate green (72 files / 476 tests).

## Deferred — Track-B (protocol/KAT-affecting, council-gated)

| ID | Item | Why deferred | Source |
|---|---|---|---|
| TB-1 | Expose optional **context string** in the signing wrapper (FIPS 204 §5.2 / FIPS 205 domain separation) | Adds an API surface; the empty-ctx path must stay byte-stable; needs council + KAT review | FIPS 204 §5.2 |
| TB-2 | Confirm/pin `@noble` hedged-vs-deterministic ML-DSA variant | Verification + possible config; affects signing behavior | FIPS 204 §3.4 |
| TB-3 | Memory zeroization of secret material | JS cannot guarantee; belongs to the Rust hot-path | FIPS 203 §3.3 / 204 §3.6 |

## Context / rationale findings

- **PQC family taxonomy** (djb §1): hash-, code-, lattice-, multivariate-, and
  secret-key families all resist Shor; Nerion's lattice (ML-KEM/ML-DSA) + hash
  (SLH-DSA) choices sit in two independent families — a deliberate diversity hedge.
- **Grover-only symmetric impact** (djb §2): justifies Nerion's AES-256 / SHA-384
  sizing (doubling vs Shor's break of RSA/ECC).
- **SANS Govern-AI** = "documented, auditable, standards-aligned" — the exact
  property Nerion makes cryptographic (see hardening map).

## Large-volume takeaways (targeted read; synthesis pending clean council run)

- **CyBOK v1.1.0** — authoritative Knowledge Areas (Cryptography, Distributed
  Systems Security, Formal Methods, Secure Software Lifecycle) to cross-reference
  into `THREAT_MODEL.md`/`ASSURANCE.md` as a recognized taxonomy backbone.
- **SEv3 (Security Engineering)** — protocol-failure patterns, API security, and
  supply-chain chapters applicable to the kernel/ledger; candidate threat-model
  enrichment.
- **978-981-19-7644-5 / 9789819612185** — lattice implementation-security,
  side-channels, and consensus/BFT + formal-verification material; informs the
  Rust hot-path hardening and the TLA⁺ consensus model (`apex/beyond-apex-wave2`).
- **Post-Quantum Cryptography Comprehensive Guide / NIST CSWP.29** — crypto-agility
  and migration patterns; Nerion's suite-agility (`crypto/src/suites.ts`, KEM/sig
  registries with pending-stub agility for HQC/Falcon) already reflects this.

> Next pass: re-run the council synthesis (rate-limit permitting) to convert the
> 161 raw findings + large-volume takeaways into a fully cited, per-finding backlog,
> and fold the CyBOK/SEv3 taxonomy cross-references into the threat model.
