# GOV-POLICY-ALGEBRA — provable totality, order-independence, conflict-freedom for the verb policy

> Status: research-engineering. UNAUDITED, pre-FTO. Additive analyzer + tests only — no change
> to `tierOf` or any decision behaviour, no wire format / KAT, no `Ps1` / `ps-*.json`, no
> cross-decision state. Branch-only.

## What

`kernel/src/policy.ts` tiers actions by **first-matching prefix** (segment-wise). That makes rule
ORDER semantically load-bearing: a mis-ordered list can silently shadow a rule (the PS-KERNEL-03
mis-tiering class). `kernel/src/policy-algebra.ts` adds a pure static analyzer, `analyzePolicy(policy)`,
that certifies three properties a generic engine (Cedar / OPA / UCAN) does **not** guarantee for the
verb-governance fragment:

- **Totality** — `tierOf` is a total function: no gaps (`defaultTier` covers the complement) and every
  outcome is a valid `RiskTier`. Property-tested over arbitrary action types.
- **Order-independence** — no two tier rules have overlapping namespaces with **differing** tiers. When
  this holds, `tierOf` is **invariant under any permutation** of the rule list — checked two ways: a
  sampled fast-check shuffle of `DEFAULT_POLICY`'s 11 rules, AND an **exhaustive all-24-permutations**
  check on a 4-rule policy. The contrapositive is shown too (a flagged policy has a permutation that
  changes a decision).
- **Conflict-freedom** — no rule is **shadowed** (made unreachable) by an earlier, more-general rule with
  a different tier; no duplicate prefixes; no action both denied and transformed (deny is checked first,
  so a clashing transform is dead code); and no **malformed prefix** with an empty namespace segment
  (empty / leading-dot / `..`) — a trailing-dot namespace marker like `payment.` is valid (`DEFAULT_POLICY`
  uses it).

`assertWellFormedPolicy(policy)` is an optional load-time / CI gate that throws on any blocking
diagnostic. Segment-wise coverage mirrors `tierOf` exactly, so siblings like `data.read` /
`data.readX` are correctly treated as disjoint (not falsely flagged).

## Why it is beyond the prior bar

The kernel previously had no notion of policy soundness — a shadowed or order-dependent policy would
simply mis-tier at decision time. A provably-total, conflict-free, order-independent verb-only algebra
is both more expressive (rules can be reordered/merged safely once certified) and carries a
no-gaps / no-shadow guarantee no mainstream policy engine offers for this fragment. The benchmark
framing is a **count, not a perf number**: *N injected shadow/gap faults, M caught* (the test injects 5
general-before-specific shadows and the analyzer catches 5/5), plus the binary permutation-invariance
property — never an "audited"/"proven-secure" claim.

## Scope / honesty

- Pure analyzer + tests; `tierOf` and the kernel decision path are **unchanged** (additive). Wiring
  `assertWellFormedPolicy` into policy ingestion is a deliberate follow-up — it would turn a
  previously-accepted-but-shadowed policy into a fail-closed reject (a behaviour change).
- The TLA+ policy-totality theorem named in the frontier item needs a TLAPS toolchain (confirmed absent
  in the build env); this ships the executable analyzer + property tests, not a machine-checked proof.
- Order-independence and conflict-freedom are distinct: a `specific-before-general` policy is
  conflict-free (reachable) yet still order-dependent (reordering would shadow the specific rule). Both
  are reported separately.

*Origin: Beyond-Apex Frontier item GOV-POLICY-ALGEBRA (see
[BEYOND_APEX_FRONTIER.md](./BEYOND_APEX_FRONTIER.md)); the govern-the-verb-moat lens.*
