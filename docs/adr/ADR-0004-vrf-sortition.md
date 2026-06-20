# ADR-0004: VRF-based private leader sortition + view-change liveness

**Status:** Proposed (design hardened by the multi-agent team + multi-model council; implementation
pending the team's grounded `@noble` feasibility spec). Closes **LEDGER-001 / LEDGER-002**.

## Context

The P4 ledger (`ledger/src/sortition.ts`) selects the round leader with a **deterministic, publicly
computable** stake-weighted hash: `selectLeader(set, prevHash, round)`. Two documented gaps:

- **LEDGER-002 (grind / predictability):** anyone can compute the leader in advance, enabling
  **leader-targeting DoS**; and a malicious prior proposer can influence the seed.
- **LEDGER-001 (liveness):** there is no **view-change / timeout** — an offline leader stalls the chain.

We want a **private, verifiable, grind-resistant** leader election (unpredictable until the leader
reveals a proof) plus a **liveness fallback**, while keeping post-quantum safety.

## Decision

### 1. VRF: `ECVRF-EDWARDS25519-SHA512-ELL2` (RFC 9381 §5.1)

Use the **standardized** RFC 9381 ciphersuite over `@noble/curves` ed25519. **Not** "ristretto255" —
RFC 9381 defines **no** ristretto255 ciphersuite (only P-256 and Edwards25519); the ristretto variant
lives in a separate, unfinished CFRG draft. Correctness is pinned offline against the **RFC 9381
Appendix A test vectors** (never roll our own — primitive built strictly on `@noble`).

### 2. Randomness beacon: chained VRF outputs (NOT the block hash)

`seed_h = VRF_beta` of height `h-1`'s finalized leader; `seed_0 = ` a fixed genesis constant. Seeding
from the **previous block hash is grindable** (the prior proposer shapes block content to bias the next
draw) — every council seat flagged this. Chaining the prior leader's VRF *output* removes the grinding
surface: a proposer must commit to the proof that *is* the next seed, and changing it changes their own
eligibility.

### 3. Stake-weighted, single-leader eligibility (Algorand-style)

Validator `V` is eligible at height `h` iff `int(VRF_beta_V(seed_h)) / 2^256 < threshold(stake_V)`,
with the threshold calibrated so the expected number of eligible validators per round is small (~1).
Eligibility is **verifiable**: anyone checks the VRF proof + recomputes the threshold. Among eligible
validators, the **lowest VRF priority wins** (tie-break on raw `beta`); honest validators attest only
the highest-priority valid block they see in the gossip window, so only one block finalizes (≥2/3).

### 4. View-change / liveness

- **Zero eligible** (no validator passes the threshold) or an **offline leader**: after a round timeout
  `Δ`, validators begin a view-change.
- **Fallback proposer:** a *deterministic* stake-sorted rotation `(r + f) mod N` (failure counter `f`),
  carried in the block as a `fallback` flag. This sacrifices leader privacy for that slot — the standard
  price of liveness.
- **Accountable safety preserved:** exactly one block per height may finalize (the existing ≥2/3 stake
  rule + equivocation detection/slashing in `equivocation.ts`); a validator that votes for both a
  fallback and a later primary block is slashable.

### 5. Key separation

The classical VRF keypair MUST be distinct from the ML-DSA-87 signing key.

## Consequences — honest caveats (binding)

- **The VRF is classical** (ed25519 discrete log). Leader privacy is **computational, not
  post-quantum**: a future CRQC could predict the leader schedule (→ targeted DoS) but **cannot forge
  blocks or finality** (those stay ML-DSA-87 / FIPS 204). **Safety is post-quantum; only
  liveness/unpredictability rests on a classical assumption.** The council confirmed this hybrid is sound.
- **No standardized post-quantum VRF exists** — lattice VRFs are research-stage with prohibitive proof
  sizes and no NIST track. The classical-VRF + PQ-signature hybrid is therefore the pragmatic apex choice
  *today*; a PQ-VRF drop-in is future work behind the same interface.
- **Empty rounds are possible by design** and are tolerated via the view-change.
- **Synchrony assumption:** the reveal/gossip window and view-change timeout assume a bounded message
  delay; state the bound when deployed.
- **Last-revealer bias** is mitigated by the chained-VRF beacon + the highest-priority-only finality
  rule, but a formal unbiasability proof is future work.
- **View-change round-skip (LEDGER-007):** a round-`r` block proves only that round `r-1` timed out (a
  ≥2/3 cert), not a chain from round 0, so a **≥2/3 coalition** can skip to an arbitrary round to
  re-draw the VRF leader among themselves. This is a fairness weakening exploitable **only** by the
  quorum that already controls liveness; **safety is unaffected** (each block still needs its own 2/3
  attestations). A cert chain (each cert referencing the prior) is the rigorous fix. Surfaced by the
  team re-audit of the integration.
- **Mode is fixed by the validator set, not per block:** a VRF set (all validators carry a VRF key)
  rejects proof-less legacy blocks as a downgrade, and a legacy set rejects VRF blocks — so the
  predictable deterministic leader can never bypass VRF. (Downgrade surfaced + closed in review.)

## Credits

Design corrected before implementation by the multi-agent **team** (workflow research/design/synthesis)
and the multi-model **council** (Gemini, DeepSeek, Grok, Mistral) — which caught the RFC-9381
ristretto255 ciphersuite error and the block-hash-seed grinding flaw, and confirmed the classical-VRF +
PQ-signature hybrid is sound.
