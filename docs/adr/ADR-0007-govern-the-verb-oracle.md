# ADR-0007: Govern-the-verb runtime negative oracle

**Status:** Accepted — apex-upgrade #3 (final) of the "above the apex" roadmap. Promotes the build-time
clean-room grep to a portable, runtime, machine-checked certification fence.

## Context

PolarSeek's thesis and clean-room design-around is **"govern the verb, never the eye"**: the kernel
governs typed ACTIONS (type / amount / counterparty), never perception. Until now this was enforced by
a build-time linter (`tools/cleanroom-lint.mjs`, forbidden patterns F1–F8) — a *source* check. SIGA's
opposing claim is that it "owns AI perception AND governance." We want a **runtime, portable** proof
that any conforming implementation's decision is INVARIANT to perception data — something a third-party
build (or a future Rust port) must pass, not just our source tree.

## Decision

Add `conformance/src/negative.ts`: `runNegativeOracle(base, decideFn = decide)`. It loads
perception-shaped side-data from `conformance/vectors/ps-negative.json` (camera, frameSequence,
object_identity, zone_occupancy, faceVector, gaitSignature, …), injects each field — individually and
all at once — into `intent.params`, and asserts the kernel's `Decision`
(`{effect, tier, reasons, obligations, evaluatorVersion}`) is **byte-identical** to the baseline. Any
divergence is a govern-the-eye leak and fails the oracle. Wired as conformance check **C14** (14/14).

Why it is sound: `decide()` reads only `intent.type` (tier + deny/transform) and, via `resolve`,
`intent.amount` / `intent.counterparty` — **never `intent.params`** (whose own type comment says
"never perception data"). `params` is the only freeform surface where perception side-data could ride
along; the oracle certifies it cannot influence the verdict.

Clean-room hygiene: the oracle SOURCE names **no** forbidden term — it reads them as data from the
vectors file, which lives in `conformance/vectors/` (the lint skips dirs named `vectors`/`test`). So
the certification can name SIGA's exact perception primitives in order to forbid their influence,
while the scanned source stays clean.

## Consequences

- **Non-vacuous (proven):** a negative-control test injects a "leaky" `decideFn` that lets a face
  vector flip the verdict — the oracle reports `invariant: false` and names `faceVector`. So the fence
  would catch a real regression, not pass trivially.
- **Portable:** any implementer runs the same oracle over their `decide`; it is the runtime companion
  to the source linter.
- **Honest scope:** it certifies invariance to perception data carried in the freeform `params` bag —
  the only injection surface, since every other kernel input is explicitly typed. It does not (and need
  not) prove anything about perception the kernel never receives.
- **Design-around is engineering intent, not a legal opinion** — FTO still required ([FTO_TODO.md](../FTO_TODO.md)).

## Credits

Selected as roadmap #3 by the apex-upgrade team workflow (best frozen LAST, after the new receipt
surfaces). Builds on the existing `tools/cleanroom-lint.mjs` F1–F8 catalog.
