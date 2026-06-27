# PQC-1 — domain-separation label registry + conformance gate

> Status: research-engineering. UNAUDITED, pre-FTO. Additive registry + test only — changes no
> label's bytes, no wire format, no `Ps1` / `ps-*.json`, no cross-decision state. Branch-only.

## What

Domain separation is what stops a signature, MAC, KDF output, or commitment minted for one purpose
from validating in another. Nerion has **~29 domain-separation labels** scattered across ~15 modules
in **four different naming conventions** (`polarseek/x/v1`, `PolarSeek/x/v1`, `PolarSeek-X-v1`,
`polarseek-x-v1`), some versioned and some not — ADR-0026 fixed one cross-profile substitution
reactively, which is the symptom of an un-audited namespace.

`crypto/src/domain-labels.ts` makes the namespace a **single source of truth** (`DOMAIN_LABELS`),
and `crypto/test/domain-labels.property.test.ts` is a conformance gate that proves it:

| Property | Guarantee |
|---|---|
| **Uniqueness** | no label string is reused for two purposes (would merge trust domains) |
| **Prefix-freeness** | no label is a string-prefix of another (no cross-context confusion under raw-string / HKDF-info use) |
| **Coverage** | every registered label actually appears in its claimed source module (registry ≠ fiction) |
| **No inline-literal escape** | the test scans the whole protocol source tree and fails if any domain-separation literal is **not** registered or explicitly excluded — a new unregistered label breaks the build |
| **Injectivity** | distinct labels give distinct canonical encodings under `encodeCanonical` |

Parameterized labels (the disclosure range-proof `stmt`/`bit` transcripts) are registered by their
static stem. A small **explicit exclusion list** (`NON_LABEL_LITERALS`) records every source literal
that matches the naming pattern but is *not* a protocol domain-separation context (the kernel version
string, an Azure key name, the CBOM `bomFormat` tag) — each with its reason, so the no-escape scan
stays sound with no silent allowlisting.

## Why it is beyond the prior bar

There was no central registry and no coverage/prefix-free gate; ADR-0026 showed the namespace was
incompletely covered. A machine-checked global registry with a no-escape scan is ahead of the
review-only baseline: it converts "we tried to keep labels distinct" into a re-runnable proof, and it
makes the four-convention inconsistency visible for a future unification. The benchmark framing is an
**engineering-completeness count**, not security: *N labels registered, prefix-free, 0 inline escapes,
0 injectivity collisions* — never an "audited" or "secure" claim.

## Scope / honesty

- Additive: this is a registry + a gate. It does **not** change any label's bytes (those are
  wire-format / KAT-bound). Wiring each module to **import** its label from the registry (so the
  registry is load-bearing, not just authoritative-by-test) is a byte-identical follow-up, gated by
  `npm run conformance`.
- Prefix-freeness is defense-in-depth: most labels are used as a distinct CBOR array element (where
  canonical encoding is injective regardless), but the raw-string / HKDF-info usages benefit from it.
- The four naming conventions are **not** unified here (that would touch wire bytes → Track-B + KAT
  regen); this registry makes the inconsistency checkable and is the prerequisite for any such cleanup.

*Origin: Beyond-Apex Frontier item PQC-1 (see [BEYOND_APEX_FRONTIER.md](./BEYOND_APEX_FRONTIER.md));
council-elevated by the DeepSeek and OpenAI seats.*
