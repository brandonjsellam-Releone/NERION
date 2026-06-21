<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Team Apex — Round-2 deep audit (2026-06-21)

**Scope:** a deeper, component-specialized adversarial pass after the Round-1 sweep — ZK soundness math,
VRF/sortition/consensus, light-client + gossip, keystore OTS custody, plus an explicit lens that tries to
**break the 8 fixes already landed** (Round-1 ×6 + the two ripple-heavy ones). Same discipline: every candidate
**refuted by two independent skeptics** (exploitability + scope-and-novelty); only doubly-survived findings
recorded.

**Reassurance result (important):** the *break-the-fixes*, *zkrange-math*, *policyproof*, and *keystore-ots*
surfaces all returned **sound, zero findings** — the 8 landed fixes held under fresh attack, the bespoke ZK
range/policy-satisfaction proofs survived a dedicated mathematical soundness pass (FS transcript completeness,
bit-decomposition, OR-proofs, point validation, the n≤251 cap), and the HBS/LMS one-time-signature custody
showed no index-reuse path. **3 new confirmed findings** were on the consensus/networking surface.

## Fixed in this session (gate green)

### LEDGER-VRF-001 — negative/non-integer round grinds VRF sortition past the view-change cert (HIGH)
`ledger/src/chain.ts` `verifyFinalized` + `proposeVrf`. The view-change-cert requirement was gated on
`round > 0`, and `vrfAlpha(prevHash, round)` fed `round` into the VRF with no lower bound or integer check. A
**sub-1/3** (e.g. 1%-stake) proposer could grind `round = 0, -1, -2, …`, computing its deterministic β per
round until `vrfLeaderEligible` is true, then publish a **cert-less** block at that negative round —
`verifyFinalized` certified it as a legitimate eligible leader (grind-resistance / leader-unpredictability
break; not a standalone safety break since finality still needs 2/3 attestations, but the property the VRF
exists to provide). Distinct from the disclosed LEDGER-007 (a ≥2/3 coalition skipping *forward* with a *valid*
cert). **Fix:** reject `!Number.isSafeInteger(round) || round < 0` in both `verifyFinalized` (a verdict reason)
and `proposeVrf` (throws). Regression test: a block with `round = -1` fails verification.

### GOSSIP-CENSOR-001 — unvalidated attestation pool → zero-stake censorship of finality (HIGH)
`ledger/src/gossip.ts` `onAttestation`. The pool was **first-writer-wins** with NO validation — no signature
check, no validator-set membership, no suite/height check — keyed by `blockHash` and deduped by `validator`.
A **zero-stake, no-key** gossiper could flood garbage-signed attestations `{blockHash:h, validator:V, …, sig:garbage}`
for every honest `V`, occupying each `(h,V)` slot first; the genuine attestation then hit the dedup, was
dropped **and not re-flooded**, so `attestationsFor(h)` returned only garbage, the safety verifier discarded it
all, and the block **never finalized network-wide** — a permanent liveness/censorship break in exactly the
Byzantine-gossip model the module claims to defend. **Fix:** validate on ingress — drop any attestation whose
`suite !== this.suite`, whose validator has `stake <= 0`, or whose signature fails
`verifyAttestationSig` (exported from `chain.ts`, binds suite+height+hash) — so only genuine attestations ever
occupy a slot. Regression test: a garbage-attestation flood preceding the block no longer prevents finalization.

### GOSSIP-DOS-001 — unbounded orphan-attestation pool (MEDIUM)
`ledger/src/gossip.ts`. The attestation map had no cap on distinct `blockHash` keys, no membership gate, and no
expiry (orphans for never-received blocks were retained forever — `drainBuffered` only pruned hashes of *known*
sub-head blocks). **Fix:** the ingress validation above (a valid attestation needs a real staked signature, so
fabricated-hash spam is rejected), plus a live-height window `att.height ∈ [height, height+MAX_FUTURE_HEIGHTS]`
(height is now signature-bound), a `MAX_ATTESTED_HASHES` cap, and sub-head orphan pruning in `drainBuffered`.

## Method note

Round 2 confirms the value of an adversarial pass over already-fixed code: it re-validated the 8 fixes rather
than assuming them, and the zero-finding surfaces (ZK math, OTS) are positive assurance for the external audit,
not silence.

## Round-2b (the 6 throttled surfaces) — 1 real finding the automated gate missed

The dual-refuter gate returned 0 confirmed, but three finder *summaries* described concrete candidates the
gate had dropped (a dropped refuter under the burst rate-limit forces `is_real=false`). Manual verification of
those summaries — in BOTH directions — was decisive:

### RCPT-002 — the receipt's `inputHash`/`decisionHash` re-leak the amount (HIGH) — **FIXED**
`receipts/src/receipt.ts`. The RCPT-001 fix salted `commitments.intent`, but the SAME public log leaf still
carried `commitments.inputHash = SHA3(encodeCanonical(KernelInput))` (and `decisionHash`, which embeds it) —
**unsalted SHA3 over the full input, which contains the low-entropy `amount`**. An observer who knows the rest
of the input brute-forces the amount from the leaf exactly as in RCPT-001/CB-001 — bypassing the salted intent
commitment. No code recomputes those fields (verified), so they could be made hiding without breaking
verification. **Fix:** commit them as `commitField(replayHash, intentSalt)` with the same off-leaf salt, so the
whole leaf is hiding; an authorized auditor recomputes with the salt. Regression test: the input/decision-hash
commitments are salted (differ per receipt, ≠ raw, ≠ unsalted). *The selective-salt finder caught what the
refuter gate dropped — manual verification of dropped candidates earned its keep.*

### Rejected on inspection (NOT findings)
- **supply-chain COSE "missing domain separation":** the SBOM/SLSA statements are **self-describing per their
  standards** (`bomFormat: CycloneDX`, `_type: in-toto/Statement/v1`, `predicateType: slsa.dev/provenance/v1`);
  adding a Nerion-specific `externalAad` would **break** the standard-COSE/SCITT/in-toto external verifiability
  that is the module's explicit goal. Correctly dropped.
- **COSE alg-confusion:** `alg` is hardcoded to `ML_DSA_87` and decoupled from `suite` — real but **latent**
  (every active suite uses ML-DSA-87, and the verifier always pins `suite`), non-exploitable today; recorded as
  a follow-up hardening (derive the COSE alg from the suite's sig scheme when a non-ML-DSA suite is added).

### Sound, zero findings
AEAD nonce (GCM is used ONLY in deterministic KAT fixtures; all at-rest sealing delegates to KMS/HSM — no
production GCM nonce path), spec-vs-code (attenuation monotonicity + aggregate-overflow held under adversarial
grant fields; the one divergence — grant's OWN signed numeric fields not integer-validated — is self-protected
by `isAttenuationOf` and non-exploitable), and translog/receipts Merkle (no wrong-root forgery; the
cross-size "accepts" are the by-design RFC6962 property that the STH signature authenticates tree size).
