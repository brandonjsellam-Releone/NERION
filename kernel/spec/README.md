# kernel/spec — machine-checked model of the admission kernel

`PolarSeekKernel.tla` is the formal statement of the kernel's safety properties:

1. **AttenuationMonotone** — delegation never amplifies authority.
2. **DefaultDeny** — no authorizing capability ⇒ deny.
3. **AllowImpliesAuth** — an `allow` implies some capability authorized the intent.
4. **Determinism** — the decision is a pure function of its inputs.

## Status (honest)

The module is **authored but not yet machine-checked in this environment** — the
P0/P1 build host has no Java / TLC / TLAPS toolchain. The **executable
counterpart is green**: the same properties are exercised by property-based
tests over randomized inputs in:

- `capabilities/test/attenuation.property.test.ts` — AttenuationMonotone (fast-check).
- `kernel/test/kernel.test.ts` — DefaultDeny, AllowImpliesAuth, fail-closed.
- `kernel/test/replay.test.ts` — Determinism (byte-identical ReplayBundle).

Property tests refute counterexamples across thousands of cases but are not a
proof. Closing the gap is a tracked P1/P2 item: run TLAPS (or port to Lean) in
CI. Until then, do not claim the properties are "formally proven" — claim they
are "modeled and property-tested".

## Running it (once a toolchain is provisioned)

```
# TLC model check (bounded) — choose finite CONSTANTS in a .cfg:
java -jar tla2tools.jar -config PolarSeekKernel.cfg PolarSeekKernel.tla
# Or discharge the THEOREMs with the TLA+ Proof System (TLAPS).
```
