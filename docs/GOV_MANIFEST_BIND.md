# GOV-MANIFEST-BIND — bind the declared Action-Manifest to the enforced decision

> Status: research-engineering. UNAUDITED, pre-FTO. Additive predicate + tests only — no decision-path
> change, no wire format / KAT, no `Ps1` / `ps-*.json`, no cross-decision state. Branch-only.

## What

The Action Manifest (ADR-0025 / ADR-0030 — the EU-AI-Act Article-13 audit-legibility surface) is a
projection that *self-asserts* a `riskClass` (T0..T3) and a `policyHash`. Nothing checked that those
declarations match what the kernel actually does, so a deployer could present a manifest that
**understates the applied tier** — the verbId↔tier "semantic laundering" flagged in `docs/FRONTIER.md`.

`kernel/src/manifest-bind.ts` adds a pure consistency predicate:

- `manifest.riskClass` must equal `T${tierOf(intent, policy)}` — the tier the kernel actually applies.
- `manifest.policyHash` must equal a domain-separated canonical hash of the policy —
  **kernel-version-independent** (a kernel upgrade with an unchanged policy must not invalidate
  manifests; the receipt separately carries the kernel identity via `evaluatorVersion`).

`checkManifestConsistency(manifest, intent, policy)` returns `{ consistent, mismatches }`;
`assertManifestConsistent(...)` is the throwing gate form for a permit issuer / verifier / auditor.
The test proves a consistent manifest passes, a relabelled-tier manifest is rejected, a wrong
`policyHash` is rejected, **12/12** injected laundering attempts are caught, and the property
"consistent IFF it declares the true applied tier".

## Why it is beyond the prior bar

No emerging agent-auth standard (draft-klrc-aiagent-auth, EUDI-VC, W3C-VC) binds a **declared** risk
class to an **enforced** decision — a VC simply carries whatever the issuer asserts. Cryptographically
tying the audit-legible verb to the kernel's applied tier + evaluator identity is what makes
"execution governance" auditable rather than merely attached. Marked **INCREMENTAL** honestly: the
manifest is a projection computed *after* admission, so this is defense-in-depth / audit-legibility,
not a core security boundary.

## Scope / honesty

- Additive and OPTIONAL: the kernel does **not** call this on the decision path — that path stays a
  pure, params-blind function. It is currently an optional audit-consistency check; it reduces the
  laundering surface only once wired into permit issuance / verification (the follow-up).
- `policyHash` binds to a **kernel-version-independent** domain-separated hash of the policy (council
  fix: `evaluatorVersion` coupled the manifest to the kernel build, needlessly invalidating manifests
  on a kernel upgrade). The receipt independently carries the kernel+policy identity via `evaluatorVersion`.
- **Scope:** binds the declared **tier** and **policy identity** (closes verbId↔tier laundering). It
  does **not** bind the allow/deny/transform **effect** — the manifest has no effect field today, and
  adding one is a wire-affecting manifest-schema change (tracked follow-up); within-tier effect
  laundering is out of scope here.
- EU-AI-Act framing is **technical alignment only** — never a "compliant AI system" or conformity
  claim. UNAUDITED / pre-FTO.

*Origin: Beyond-Apex Frontier item GOV-MANIFEST-BIND (see [BEYOND_APEX_FRONTIER.md](./BEYOND_APEX_FRONTIER.md)).*
