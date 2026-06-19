# PolarSeek — Apex Hardening Review

Scope: TypeScript monorepo at `C:/Users/User/polarseek` (post-quantum AI-action
governance). Findings below were confirmed by reading the actual source and, for
the marquee items, by building working forgeries / fail-open probes against the
real exported code (vitest, `@noble` v2 as vendored in `node_modules`). Probe
files were removed after use.

Each finding gives `file:line`, a concrete fix, and a note on test coverage.
Where the supplied finding text described an older revision of the code, the
correction is stated explicitly — the underlying vulnerability and fix still hold
against the current source unless noted otherwise.

---

## Top fixes first

1. **CRITICAL — ZKRANGE-001**: `verifyBelow` trusts attacker-controlled
   `proof.n`; with `n = 253` a forged proof that `100 < 100` (and `10^30 < 5`)
   verifies `true`. Total break of range-proof soundness.
   `disclosure/src/zkrange.ts:199-208`.
2. **HIGH — PS-CAP-01**: non-finite / non-integer `intent.amount` (`NaN`,
   `-Infinity`, `1.5`) silently passes BOTH the per-action ceiling and the
   aggregate cap — fail-open in the authority firewall.
   `capabilities/src/grant.ts:24-28`.
3. **MEDIUM — PS-CAP-02**: negative `intent.amount` passes ceilings and reduces
   the observed aggregate (a credit/reversal smuggled as a negative transfer).
   `capabilities/src/grant.ts:24-28`.
4. **MEDIUM — PS-KERNEL-01**: `replay()` never cross-checks
   `bundle.evaluatorVersion`, contradicting its documented tamper-evidence
   invariant. `kernel/src/replay.ts:34-42`.
5. **LOW — PS-SETTLE-01**: `MeteringLedger.grant` double-credits on a duplicate
   `nonce` (no idempotency), so the same signed grant re-applied mints balance
   again. `settlement/src/credits.ts:54-71`.

Items 2 and 3 share a single one-line fix (validate the amount once at the top of
`authorizesIntent`); doing 1, 2/3, and 4 closes every confirmed authority/soundness
hole found in this review.

---

## CRITICAL

### ZKRANGE-001 — `verifyBelow` trusts attacker-controlled `proof.n`, allowing modular wraparound that forges any range claim
- **File**: `C:/Users/User/polarseek/disclosure/src/zkrange.ts:199-208` (the
  unbounded read of `proof.n` is at line 200; aggregation check at lines 203-207).
- **Status of supplied text**: the *vulnerability and fix are CONFIRMED against
  the current code*, but the supplied `detail` describes a now-superseded single-
  sided implementation (line refs 159-168, weak-FS challenge at 78-88). The
  module has since been rewritten to a **two-sided** proof — `verifyBelow` now
  requires BOTH `amount ∈ [0, 2^n)` (bound to `C`) AND
  `diff = threshold-1-amount ∈ [0, 2^n)` (bound to `cDiff = G^(threshold-1) − C`),
  and the Fiat-Shamir challenge now binds the full statement via `statementHash`
  (lines 91-95). That rewrite closes the *old* single-sided / weak-FS attack but
  **does not** close this one.
- **What was verified empirically**: `L = Point.Fn.ORDER` (line 30) is the
  ristretto255 scalar order; `L.toString(2).length === 253`, so
  `(1n << 253n) > L`. `verifyBelow` reads the bit-length `n` directly from the
  prover's proof object (`const n = proof.n`, line 200) with **no equality check
  against a verifier-fixed value and no upper bound** (line 201 only computes
  `bound = 1n << BigInt(n)`; the only gate is `threshold ≤ bound`, line 202,
  which an attacker trivially satisfies by enlarging `n`). I replicated the
  module's exact primitives (`G`, `H = hashToCurve('PolarSeek/disclosure/generator-H/v1')`,
  `proveBit`, `buildBits`, `statementHash`) and, with `n = 253`, set the forged
  diff to the residue `mod(threshold-1-amount) = L-1` (≡ −1 mod L, encoding a
  *negative* integer diff). `buildBits` decomposes `L-1` into 253 honest `{0,1}`
  bit commitments whose weighted sum equals `cDiff`, and the `mod(-r)` blinding-
  balance (line 188 / 145) makes the `H`-component match. Calling the **real**
  exported `verifyBelow(commit(100n, r), 100n, forged)` returned **`true`** — a
  verifying proof that `100 < 100`. Both `verifySub` aggregation checks
  (lines 166-167) and all per-bit `verifyBit` checks (lines 168-172) passed.
- **Why the rewrite did not help**: the two-sided construction assumes
  `n` is fixed so that `Σ b_i·2^i` is a genuine non-negative integer
  `< 2^n << L`. Once the attacker chooses `n ≥ 253`, *any* residue mod L
  (including ones encoding a negative diff) is a valid `{0,1}` bit-decomposition,
  so the "diff ∈ [0,2^n)" leg proves nothing over the integers. The amount leg is
  satisfied honestly (`amount = 100` fits in 253 bits).
- **Test coverage gap**: `disclosure/test/zkrange.test.ts:20-27` exercises only
  the honest *prover* rejecting out-of-range amounts (`proveBelow(1n<<32n, …)`
  throws). No test ever hands `verifyBelow` an attacker-chosen `proof.n`. The
  live conformance check `conformance/src/suite.ts:300-306` (C11) likewise uses
  only honest proofs. The hole is real and untested.
- **Concrete fix**:
  1. Do not take `n` from the proof. Make the expected bit-length an explicit
     verifier parameter / protocol constant:
     `export function verifyBelow(commitment, threshold, proof, n = 32)` and
     reject unless `proof.n === n`.
  2. Independently hard-cap to prevent wraparound regardless of caller:
     require `Number.isInteger(proof.n) && proof.n >= 1 && proof.n <= 252` (so
     `(1n << BigInt(n)) < L`) and require `threshold - 1n < (1n << BigInt(n))`
     so the diff range is fully representable.
  3. The honest prover already defaults `n = 32` (line 180), inside the safe
     bound — keep `n` a fixed protocol constant, never negotiable via the proof
     object. (The statement-binding in `statementHash`/`challenge` is already in
     place after the rewrite, so no additional FS work is required for this fix.)
- **Caveat (does not reduce severity)**: the module self-labels
  UNAUDITED REFERENCE / not-for-production (zkrange.ts:7-11) and external audit
  of exactly this file is already flagged in `docs/STRENGTHEN.md` and
  `docs/STATUS.md:18`. The break is nonetheless real, total, and exploitable
  exactly as shown.

---

## HIGH

### PS-CAP-01 — Non-finite / non-integer `intent.amount` bypasses every numeric ceiling (fail-open)
- **File**: `C:/Users/User/polarseek/capabilities/src/grant.ts:24-28`.
  `const amount = intent.amount ?? 0` (line 24); guards
  `amount > grant.perActionCeiling` (line 25) and
  `ctx.observedAggregate + amount > grant.aggregateCap` (line 26).
- **Verified empirically** by calling the real `authorizesIntent` with a
  finance-flavored grant (`perActionCeiling: 500`, `aggregateCap: 2000`):
  - `amount = NaN` → `authorizesIntent(...) === true` against **both** finite
    ceilings AND a `null` per-action ceiling. (`NaN > x` is `false`,
    `observed + NaN > cap` is `false`.) Strongest vector.
  - `amount = -Infinity` → `true` (bypasses both).
  - `amount = 1.5` (non-integer) → `true` (also bypasses; covered by the same
    fix).
  - `Number.isSafeInteger` rejects `NaN`, `±Infinity`, and `1.5`, while
    accepting valid integers — confirmed.
- **Factual correction to the supplied `detail`**: the claim that `+Infinity`
  bypasses is **wrong**. With any finite `perActionCeiling`,
  `Infinity > ceiling` is `true` (denies); with `perActionCeiling = null` but a
  finite `aggregateCap`, `observed + Infinity > cap` is `true` (denies). `+Infinity`
  is correctly caught. The real bypass vectors are **NaN** (works against finite
  OR null ceilings) and **-Infinity** (and non-integers like `1.5`). The marquee
  NaN vector the finding leads with is fully valid; severity is unaffected.
- **Reachability**: the full path is unvalidated — `planes/src/node.ts:65-73`
  copies `req.intent` into `KernelInput` unchecked; `kernel/src/kernel.ts:35` runs
  `tierOf` (`policy.ts:18-23` keys only off `intent.type`, never `amount`) then
  `resolve`; `capabilities/src/resolver.ts:37` calls `authorizesIntent` directly.
  No shape/finiteness check anywhere upstream. `types.ts:24` only *documents*
  "Integers only — no float nondeterminism"; nothing enforces it. The property
  test `capabilities/test/attenuation.property.test.ts:58` generates
  `amount` only in `fc.integer({min:0,max:3000})`, so it structurally cannot reach
  this.
- **Concrete fix**: at the top of `authorizesIntent` (and/or as an intent-shape
  guard in `decide`), before the ceiling comparisons:
  ```ts
  if (intent.amount !== undefined && !Number.isSafeInteger(intent.amount)) return false
  ```
  Treat any amount that is not a finite safe integer as unauthorized. Recommend
  also dropping the `+Infinity` claim from the inline comment / any tracking note
  and leading with NaN / -Infinity.

---

## MEDIUM

### PS-CAP-02 — Negative `intent.amount` passes ceilings and reduces the observed aggregate
- **File**: `C:/Users/User/polarseek/capabilities/src/grant.ts:24-28` (same
  guards as PS-CAP-01; no lower-bound check).
- **Verified empirically**:
  - `amount = -1000`, `perActionCeiling = 500` → `-1000 > 500` is `false`, so the
    per-action ceiling does not deny. `authorizesIntent === true`.
  - With `observedAggregate = 1900`, `aggregateCap = 2000`, `amount = -1000` →
    `observedAggregate + amount = 900`, `900 > 2000` is `false`, so the rolling
    cap is not tripped and the per-decision aggregate is *reduced* below
    `observedAggregate`. `authorizesIntent === true`.
- **Why it matters**: for value-bearing action types (e.g. `payment.transfer`) a
  negative amount is semantically a reversal/credit. The grant layer applies its
  ceilings as if all amounts were non-negative, so per-action ceilings are
  silently ineffective against negatives and the rolling aggregate is understated.
- **Corroborating intent**: `settlement/src/credits.ts:55` already rejects
  non-positive amounts (`if (!Number.isInteger(amount) || amount <= 0) throw`),
  proving the project treats negative amounts as invalid in the value path — the
  authorization layer simply omits the same guard. The property test never
  exercises negatives (`attenuation.property.test.ts:58`, `min:0`).
- **Severity rationale**: medium rather than high because `observedAggregate` is
  an externally-supplied signed scalar (`types.ts:9,76`), so a single intent does
  not directly decrement a persisted counter; the impact is the ceiling bypass
  plus the understated per-decision aggregate, and full reachability depends on
  upstream input validation not present in the reviewed code.
- **Concrete fix**: fold into the PS-CAP-01 guard so a single check covers both —
  require a finite **non-negative** safe integer:
  ```ts
  if (intent.amount !== undefined && (!Number.isSafeInteger(intent.amount) || intent.amount < 0)) return false
  ```

### PS-KERNEL-01 — `replay()` never cross-checks `bundle.evaluatorVersion`
- **File**: `C:/Users/User/polarseek/kernel/src/replay.ts:34-42`.
- **Verified by source reading**: `ReplayBundle.evaluatorVersion` is documented as
  "Pinned evaluator version at capture time (cross-checked on replay)"
  (replay.ts:19-20) and the file header (lines 1-8) promises byte-identical
  re-derivation of the decision AND receipt. But `replay()` reads only
  `bundle.inputBytes`: it decodes the input (line 35), calls `decide(input)`
  (line 36, which recomputes `ev = evaluatorVersion(input.policy)` from the
  embedded policy — kernel.ts:33), then at line 39 computes `receiptHash` over
  `decision.evaluatorVersion` (the freshly recomputed value). `bundle.evaluatorVersion`
  is **never referenced** in the function body. `evaluatorVersion` is imported
  (line 13) but used only by `buildReplayBundle` (line 31).
- **Consequence**: a `ReplayBundle` whose pinned `evaluatorVersion` disagrees with
  the policy embedded in `inputBytes` replays "successfully" and emits a receipt
  bound to the recomputed version, silently masking the kernel/policy mismatch the
  field exists to detect. The promised tamper-evidence on the evaluator pin is
  absent. `kernel/test/replay.test.ts` only checks determinism (same bundle →
  same hash), never a tampered/mismatched pin.
- **Concrete fix**: in `replay()`, after `decide`, fail closed on mismatch:
  ```ts
  if (decision.evaluatorVersion !== bundle.evaluatorVersion) {
    throw new Error('replay: evaluatorVersion pin does not match recomputed evaluator')
  }
  ```
  (equivalently assert `evaluatorVersion(input.policy) === bundle.evaluatorVersion`),
  so the captured pin is actually verified.

---

## LOW

### PS-SETTLE-01 — `MeteringLedger.grant` double-credits on a duplicate `nonce` (no idempotency)
- **File**: `C:/Users/User/polarseek/settlement/src/credits.ts:54-71`.
- **Detail**: `grant(account, amount, nonce)` validates `amount` (line 55) then
  unconditionally does `this.balances.set(account, this.balance(account) + amount)`
  (line 58) and signs `[GRANT_CONTEXT, account, amount, nonce]` (lines 59-62).
  The `nonce` field exists (and is in the signed bytes) clearly to make a grant a
  unique, idempotent mint, but **nothing tracks seen nonces** — calling `grant`
  twice with the same `(account, amount, nonce)` credits the balance twice and
  returns the same valid signature. There is no dedup in `grant`, no replay set,
  and `verifyGrant` (lines 88-98) happily re-verifies the reused grant.
- **Why low**: this is an explicitly in-memory, non-production metering ledger
  (module header lines 1-9 defers the real fungible/transferable token), and there
  is no transfer path. Impact is confined to balance inflation within a single
  in-process ledger instance. But the unenforced nonce is a latent integrity gap
  in the one minting path, and the test suite (`settlement/test/credits.test.ts`)
  only ever uses distinct nonces, so it is uncovered.
- **Concrete fix**: track consumed nonces and reject reuse:
  ```ts
  private readonly seenNonces = new Set<string>()
  // in grant(), after the amount check:
  const key = `${account}|${nonce}`
  if (this.seenNonces.has(key)) throw new SettlementError('duplicate grant nonce')
  this.seenNonces.add(key)
  ```
  (Or key the nonce globally if a nonce must be unique across all accounts.)

---

## Areas reviewed and found clean (no defensible finding)

These were read closely and showed no concrete exploitable issue:

- `crypto/src/symmetric.ts` — `constantTimeEqual` (lines 29-37) is length-checked
  and branch-free; `HMAC_SHA384.verify` uses it; AES-GCM `open` maps tag failure to
  a thrown `VerificationError`. Sound.
- `crypto/src/envelope.ts` / `planes/src/permit.ts` — to-be-signed / to-be-MAC'd
  structures are domain-separated and bind the SuiteID; `verifyPermitForAction`
  checks MAC, audience, action hash, expiry, and optional session. Sound binding.
- `capabilities/src/capability.ts` — `verifyChain` checks `issuer === signer`,
  signature, root-in-trusted-set, delegator-holds-parent-subject, and
  `isAttenuationOf` at every link; `narrow` intersects every dimension. The C5
  property test backs "attenuation never amplifies."
- `crypto/src/suites.ts` / `kem.ts` / `sign.ts` — only `active` suites are
  negotiated (`negotiate` filters on `activeSuiteIds`), pending KEMs/signers throw
  `NotImplementedError`, hybrid KEMs come straight from `@noble/post-quantum/hybrid`.
- `translog/src/merkle.ts` / `sth.ts` — RFC 6962 leaf/node domain separation;
  inclusion/consistency verification is wrapped in try/catch and fails closed.
  Note: `detectEquivocation` (sth.ts:64-76) intentionally does not verify STH
  signatures — it dedups by `operator@size`; callers must `verifyTreeHead` first.
  This matches the documented contract, so it is not flagged, but it is worth a
  doc/usage note so an unverified forged STH is never fed in as authoritative.
- `governance/src/quorum.ts` — `enact` dedups distinct valid member signers and
  checks the validity window; `verifyApproval` binds `proposalId`.
- `ledger/src/chain.ts` / `sortition.ts` — `verifyFinalized` checks prevHash,
  sortition leader, proposer sig, distinct attestations with positive stake, and
  the finality fraction; deterministic stake-weighted leader selection is sound
  (private VRF correctly noted as future work).
