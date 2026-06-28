# Frontier Integration v1 — composing the 9 Beyond-Apex branches

> Status: research-engineering integration branch. UNAUDITED, pre-FTO. Branch-only; the maintainer
> merges this (or the 9 individual branches applying the reconciliations below). No `Ps1` /
> `ps-*.json` change; conformance 23/23 unchanged.

## Why

The 9 Beyond-Apex Frontier branches were each gate-green **in isolation**. The full 11-seat council's
unanimous #1 concern was that nothing validated them **together** — "isolated green branches may not
compose." This branch merges all 9 and proves they do, on one tree.

## What merged (council-recommended order; registry last)

gov-params-blindness · gov-policy-algebra · gov-manifest-bind · saf3-fail-closed ·
cf2-accountable-safety · pqc4-key-committing-aead · pqc2-kem-combiner-neg · cf5-finality-metamorphic ·
pqc-domain-registry.

The only structural merge conflict was `kernel/src/index.ts` (three branches append exports at the
same anchor) — resolved by unioning the export blocks.

## Reconciliations the integration SURFACED (the value of this step)

Composing the branches made the `pqc-domain-registry` drift scan fire — it caught two
domain-separation labels that newer branches introduced and the registry didn't yet know (a finding
that, by construction, no single branch could have caught):

1. **`nerion/policy-id/v1`** (from gov-manifest-bind) — registered as a domain-separation label.
2. **`polarseek/kem-seal/key-commitment/v1`** (from pqc4) — this is an HKDF **salt**, not a context
   info-label, and it sub-namespaces the `polarseek/kem-seal` label, which would *falsely* trip the
   registry's prefix-free invariant. Classified as an **excluded non-context literal** (with reason),
   keeping pqc4's crypto byte-identical. A cleaner long-term option is to rename it prefix-free on the
   pqc4 branch; recorded here for the maintainer.

## Composition test

`kernel/test/composition.property.test.ts` exercises the governance invariants **jointly** on one
decision flow — gov-policy-algebra (well-formed policy) + gov-params-blindness (decision ignores
`params`) + gov-manifest-bind (declared ⟺ applied tier) + saf3 fail-closed (deny ⟺ no verified
authorizer) — including the adversarial case where a decision stays params-blind **while** manifest
binding still rejects a laundered manifest. Plus a crypto-compose check: a pqc4 key-committing seal
round-trips and its domain-sep labels are recognized by the pqc-domain-registry.

## Result

On the merged tree: **full gate green (81 test files, 573 tests)** and **conformance 23/23 CONFORMANT**
— the 9 upgrades compose with no regression and no wire/KAT change.

## Scope / honesty

- This validates **composition + no-regression**, not security: still UNAUDITED / pre-FTO. The council's
  deeper asks — machine-checked proofs (needs a prover toolchain) and an independent audit — remain
  open and are the next real moat.
- Several frontier docs use proof-strength verbs ("proven", "closes", "certifies") that the council
  asked to soften to "checked/property-tested/defends-against"; the artifact bodies already carry the
  honest "MEASURED, not a proof" caveats, but the maintainer should tighten the headlines at merge.

*Origin: the Beyond-Apex Frontier campaign (see [BEYOND_APEX_FRONTIER.md](./BEYOND_APEX_FRONTIER.md)).*
