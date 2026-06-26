# GOV-PARAMS-BLINDNESS — structural + unbounded proof of "govern the verb, never the eye"

> Status: research-engineering. UNAUDITED, pre-FTO. Additive type + tests only — no wire
> format, no KAT, no `Ps1` / `ps-*.json` change, no cross-decision state. Branch-only.

## What

`ActionIntent.params` is the receipt-bound payload (hashed into receipts for the audit
trail) that the admission kernel must **never read** — it is the perception channel the
design-around ([ADR-0007](./adr/ADR-0007-govern-the-verb-oracle.md)) keeps out of the
decision. Until now that invariant was substantiated by a **finite** negative-oracle vector
set (conformance C14). This change lifts it to two strictly stronger guarantees:

- **(a) Structural** — `kernel/src/blindness.ts` adds `ParamsBlind<I>` / `GovernedIntent =
  Omit<ActionIntent, 'params'>` and `governedView()`, the perception-free projection of an
  intent. Code that decides over a `GovernedIntent` *literally cannot reference*
  `intent.params`. Compile-time witnesses in the test assert the governed view excludes
  `params` and matches the exact governed-field allowlist (`type`, `resource`,
  `counterparty`, `amount`) — adding a field to `ActionIntent` becomes a **build error**
  until someone consciously classifies it as governed or perception.
- **(b) Empirical (unbounded)** — `kernel/test/params-blindness.property.test.ts` is a
  fast-check property test (fixed seed `0x6e72696f`, 200 runs/path) asserting `decide()` is
  **byte-identical** under arbitrary, adversarial `params` on the allow / deny / denylist /
  transform paths, plus a factoring test (`governedView(a) == governedView(b) ⇒
  decide(a) == decide(b)`) and an explicit colliding-keys case (params keys named after
  governed fields are still ignored).

## Why it is beyond the prior bar

The negative oracle checks a hand-curated, finite vector list; this is an **unbounded**
property over arbitrary params **plus** a **type-level** guarantee the channel cannot be
read at all. Generic policy engines (Cedar, OPA, UCAN) publish no such decision-blindness
invariant over a payload channel. The benchmark framing is a count, not a perf number:
*N randomized adversarial-params cases with 0 decision divergences* (MEASURED) and a binary
*decision path is type-level params-blind* (structural) — never an "audited"/"proven-secure"
claim.

## Scope / honesty

- Proves the **stateless per-action decision** ignores `params`; it does **not** prove the
  downstream resource honors the permit (out of scope, R6), nor is it an external audit.
- The kernel decision signature is unchanged (additive). Routing the kernel to consume a
  `GovernedIntent` end-to-end (so the projection is enforced at the call site, not only
  available) is a clean follow-up — it would also need the receipt path, which *does* hash
  `params`, to keep using the full intent.
- `governedView` uses an explicit allowlist deliberately: it excludes unknown fields by
  default (fail-closed against a future perception field leaking into the decision).

*Origin: Beyond-Apex Frontier item GOV-PARAMS-BLINDNESS (see
[BEYOND_APEX_FRONTIER.md](./BEYOND_APEX_FRONTIER.md)); council-consensus top-3 to ship.*
