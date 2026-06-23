<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->
# REV-001 — Results

## MEASURED (prototype.mjs ran successfully, node:crypto SHA3-256, DEPTH=32)

| Metric | Value | Notes |
|---|---|---|
| Non-membership proof size | **1024 B** | Constant: DEPTH × 32 B regardless of N |
| Revoke per-op | **0.1012 ms** | 32 SHA3-256 hash-ops; 500-op average |
| Prove time (N=0) | **0.0025 ms** | 2000-rep average |
| Verify time (N=0) | **0.0694 ms** | 2000-rep average |
| All sanity checks | **PASSED** | See below |

**Bug disclosure — N>0 table rows are INVALID:**
`capIndex()` extracts the first 4 bytes of the hex-padded cap-ID string.
Sequential small integers (i=0..255 all map to leaf index 0 because their
hex representation has the same leading 4 bytes when left-padded to 14 chars).
The fresh test cap also lands on this revoked leaf → `proveNonMembership`
returns `ok:false` for all N>0 rows.

This is NOT just a harness bug — DeepSeek correctly identified it as an
**architectural defect**: any cap-ID whose first-4-bytes match another
collapses to the same leaf. An adversary could craft cap-IDs that collide with
legitimate ones, revoking the legitimate cap as a side-effect. The design needs
a collision-resistant `capIndex` derivation (e.g., SHA3-256(capId) truncated
to 4 bytes) before the scalability claim holds.

**Sanity checks PASSED (distinct cap-IDs):**
- Empty tree: non-membership proof verifies for any cap
- After revoke(capA): proveNonMembership(capA) → ok:false
- Unrelated capB: valid non-membership proof under updated root
- 1-byte tamper on proof: rejected
- Stale/wrong root: rejected
- Two-revocation tree: both revoked caps denied proof; third unrelated cap valid

## MODELED / INFERRED (not measured at N>0 due to bug)

| Claim | Basis |
|---|---|
| Prove/verify times N-independent | SMT design: O(DEPTH) hash-ops regardless of N |
| Crossover (SMT vs naive list) | N≥86: 86 × 12 B = 1032 B > 1024 B SMT proof |
| State per unique revocation | ~33 nodes (1 leaf + 32 ancestors) at ~52 B/node ≈ 1.7 KB (shared paths reduce total) |

These are O(DEPTH) design properties, NOT confirmed by end-to-end measurement
at realistic N. A corrected prototype is required.

## Council adjudication — Round 1 (DeepSeek + Grok)

**Input verdict: GRADUATE (conditional)**

### DeepSeek: FIX-FIRST

Three required fixes before GRADUATE:

1. **Collision-resistant leaf indexing** — use `SHA3-256(capId)[0:4]` as leaf
   index; the current scheme is trivially broken.

2. **Freshness and root trust model** — none of the three root-distribution
   options (permit-embedded / ledger STH / out-of-band) were analyzed. Each has
   a fatal flaw without a specified freshness window and trust anchor:
   - Permit-embedded root: proves non-revocation *at issuance time* only —
     equivalent to `notAfter` with a built-in delay.
   - Ledger STH: adds a new online dependency and monitoring logic.
   - Out-of-band: no clear trust anchor; ripe for downgrade (feed an old root).

3. **Threat-model justification vs short-TTL** — "SMT wins at N≥86" compares
   against a *naive list*, not against the status quo (zero revocations, zero
   state). Short-TTL already bounds any key-compromise window. The spike never
   quantifies the TTL that Nerion actually requires or demonstrates a scenario
   where short-TTL is demonstrably insufficient.

### Grok: Do not graduate

**Key flip on the short-TTL comparison (decisive):**
> "Short-TTL degrades gracefully under key compromise — the attacker's window is
> strictly bounded. An SMT system converts that same compromise into an
> **availability or freshness attack on the revocation surface**. The spike never
> quantifies the renewal frequency required under Nerion's actual grant lifetimes,
> so the comparison remains rhetorical."

Additional Grok findings:
- Root custody: ledger embedding reintroduces governance latency; permit
  embedding makes a 5-minute-old root fatal for high-value caps; out-of-band
  recreates the single point of failure the protocol was designed to eliminate.
- Bug is not merely cosmetic: "sanity checks with distinct IDs is necessary but
  not sufficient — it does not substitute for a corrected scalability table."
- Missing: SMT root rotation, proof-of-non-revocation freshness windows,
  interaction with existing `notAfter`, adversarial index grinding analysis.

## Verdict: KILL (underspecified)

**Council unanimously declines GRADUATE.** The SMT primitive is
architecturally plausible and the measured primitives (revoke 0.1ms,
verify 0.069ms, 1024 B proof) are good numbers. But three gaps block promotion:

| Gap | Severity |
|---|---|
| Collision-resistant capIndex | CRITICAL — architectural defect, not a harness bug |
| Root distribution and freshness model | CRITICAL — without this the non-membership proof is semantically meaningless |
| Short-TTL threat-model comparison | HIGH — the status quo may be strictly simpler and the spike never demonstrates otherwise |

## Durable finding

**The SMT numbers are real but the freshness problem is the architecture.**
A 1024 B constant-size proof and 0.069 ms verify time are genuinely good
primitives. But revocation is only as fresh as the SMT root the verifier holds.
Without a root-distribution protocol that is at least as live as the notAfter
check it supplements, an SMT accumulator adds state and complexity without
adding meaningful security margin over short-TTL.

The right next step is NOT a new Lab spike — it is an **R&D paper design**:
model the root-distribution options against Nerion's concrete liveness and
threat assumptions, then return as REV-002 only if the analysis demonstrates
a clear win over short-TTL for some realistic grant-lifetime regime.

## Graduate path: REV-002 (blocked on R&D)

REV-002 prerequisites (R&D team to produce a design doc first):
1. Collision-resistant capIndex derivation (SHA3-256(capId)[0:4])
2. Root-distribution design: pick one option and formally specify freshness window + trust anchor
3. Short-TTL threat model: articulate the regime where SMT revocation adds security margin
4. Only then: corrected scalability table at N=0..10000 with diverse random cap-IDs
