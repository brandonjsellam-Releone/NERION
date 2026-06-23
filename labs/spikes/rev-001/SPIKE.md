<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->
# REV-001 — Sparse-Merkle Revocation Accumulator

**Branch:** `innovation/rev-001-revocation`
**Status:** KILL (underspecified) → revisit as REV-002
**Date:** 2026-06-24
**FTO pre-screen:** PASS — non-membership proofs / SMT accumulators are standard
cryptographic primitives predating any Nerion-adjacent claims.

## Bet

Nerion's `verifyChain()` has **no runtime revocation path**: a valid signature
chain remains valid until its `notAfter` timestamp even if the issuing key is
later compromised.  Can a Sparse Merkle Tree (SMT) revocation accumulator
provide constant-size (O(1)) non-membership proofs that compose with
`verifyChain` at negligible performance cost?

## Architecture under test

- SMT over 2³² cap-ID slots (DEPTH=32 → ≈4 billion slots)
- Hash function: SHA3-256 (already in Nerion's crypto suite, PQ-safe collision)
- Non-membership proof: DEPTH sibling hashes = 32 × 32 B = **1024 B constant**
- Revoke(capId): update leaf → recompute DEPTH ancestor hashes, O(DEPTH)
- VerifyNonMembership: reconstruct root via DEPTH hash-ops, O(DEPTH)

## FTO pre-screen result

Standard sparse Merkle tree / vector commitment literature (Ethereum, CT logs,
academic). No FTO concerns identified.

## Council seats engaged

DeepSeek (review) · Grok (review)

## Verdict

**KILL (underspecified).** The SMT primitive is architecturally plausible but
the spike has three unresolved gaps that the council identified before GRADUATE
can be considered. See RESULTS.md.
