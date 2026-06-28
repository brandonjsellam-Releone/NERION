# SAF-3 — fail-closed (default-deny) invariant witness

> Status: research-engineering. UNAUDITED, pre-FTO. Additive — **tests only**, the kernel is
> unchanged. No wire / KAT / `Ps1` change, no cross-decision state. Branch-only.

## What

The admission kernel's single most security-load-bearing property is **fail-closed**: it returns
`allow`/`transform` *only* when the resolver verified a capability that authorized the intent, and
**every** other path denies — no capability, wrong holder, expired/over-ceiling, revoked, malformed
clock/amount/aggregate, denylisted — with any unexpected exception denying at the highest tier
(PS-KERNEL-02 / CONF C8). Until now this was substantiated by a handful of specific test cases.

`kernel/test/fail-closed.property.test.ts` verifies it against an **independent spec oracle**
`shouldDeny()` (enumerated from the authorization spec, *not* the kernel impl), so the check is
necessary AND sufficient — a mere "non-deny ⟹ authorizer present" invariant would still pass if the
kernel wrongly *allowed* an expired/revoked/wrong-holder cap (council fix). The asserted properties:

- **SAFETY (no fail-open):** `effect === 'deny'` whenever the spec removes authorization.
- **LIVENESS (no wrongful deny):** `effect !== 'deny'` only when the spec authorizes — i.e.
  `(effect === 'deny') === shouldDeny(input)`, exact agreement.
- **CONSISTENCY:** non-`deny` ⟺ a verified authorizing capability is returned.

Verified two ways: a **fast-check property** (fixed seed, 500 runs) over adversarial inputs (random
verb types, negative/NaN/∞ amounts, out-of-window / NaN / ∞ / negative `now`, NaN aggregates,
present-or-absent capabilities, right/wrong holder, denylist/transform toggles, root revocation), and
an **exhaustive lattice** including explicit invalid-capability deny cases (no-cap, denylisted, wrong
holder, expired, non-finite clock, over-ceiling, revoked) plus the **exception path** (a malformed
policy that throws must deny at **tier 3**, never fail open).

## Why it is beyond the prior bar

No backlog item machine-checks deny-by-default (A5/A40 are doc reconciliation). An unbounded property
plus an exhaustive-lattice witness of "no allow without a verified authorizer" is the audit-readiness
artifact NLnet / OSTIF / ROS reviewers look for. Comparable admission engines (OPA, capability
monitors) ship example tests, not a checked no-fail-open invariant.

## Scope / honesty

- **Strong property test, NOT a machine-checked proof.** Over the finite decision lattice the
  exhaustive cases are an enumeration; the property run is sampled (400 cases, fixed seed). A true
  machine-checked theorem needs a prover toolchain (absent — see GOV-NI-PROOF / SAF-1, toolchain-gated).
- Verifies the kernel's **stateless per-action decision** against an independent spec oracle
  (safety + liveness), not just a consistency invariant — but it is a strong test, not a
  machine-checked proof. It does **not** prove the downstream resource honors the permit (out of
  scope, R6); the oracle mirrors the spec, so a spec/impl bug shared by both could still escape.
- Additive: tests only; the kernel decision path is unchanged. UNAUDITED / pre-FTO.

*Origin: Beyond-Apex Frontier item SAF-3 (see [BEYOND_APEX_FRONTIER.md](./BEYOND_APEX_FRONTIER.md)).*
