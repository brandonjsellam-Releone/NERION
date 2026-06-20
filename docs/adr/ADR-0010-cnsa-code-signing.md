# ADR-0010: CNSA 2.0 LMS/XMSS code-signing — the safe, gated subset

**Status:** Accepted (safe subset shipped; raw primitive deliberately NOT built). The gov-standards
team ranked LMS/XMSS code-signing the #3 gap; this builds the state-safety + policy + adapter pieces
PolarSeek can own and audit, and gates the rest honestly. Team-designed + adversarially verified.

## Context

CNSA 2.0 names **single-tree LMS or XMSS (NIST SP 800-208)** for software/firmware signing
(exclusive-use 2030) — a genuine gap: PolarSeek signs with ML-DSA-87/SLH-DSA, not LMS/XMSS. Two hard
facts shaped the design, both verified:

1. **`@noble` ships no LMS/XMSS** (verified against `node_modules/@noble/post-quantum` v0.6.1 — only
   ml-kem/ml-dsa/slh-dsa/falcon/hybrid). The only alternative to an adapter is rolling raw RFC 8554/8391
   hash-based-signature crypto, whose failure mode is *silent catastrophic forgery* on a single index
   reuse — the worst risk class to home-roll.
2. **SP 800-208 §8.1 validates LMS/XMSS ONLY inside a FIPS 140-3 L3+ hardware module** (no private-key
   export, in-boundary RBG). A software in-process implementation **cannot be conformant at all**.

And the defining hazard: LMS/XMSS are one-time-key schemes — **reusing any OTS index even once is a
total, unrecoverable forgery** (SP 800-208 §9.1). SP 800-208 mandates reserve-before-sign (durably
advance the index in non-volatile storage *before* a signature is exported) and forbids key
export/clone — which collides with PolarSeek's seal-the-seed custody model (a restored sealed seed =
two divergent state machines = guaranteed reuse).

## Decision

**Delegate the primitive; own the state and policy** — mirroring the existing keystore HSM adapter
pattern. Build the three safe, buildable-now pieces, gate the rest:

- `crypto/src/code-sign.ts` — a **separate** `CodeSigner` interface (async `sign(message)`, **no**
  `secretKey` arg — so it can never be a stateless `SignatureScheme` routed through seed-sealing),
  `assertSingleTree` (rejects HSS/XMSSᴹᵀ by flag **and** id), and `getCodeSigner` which throws
  `NotImplementedError` with a CONNECT pointer (the raw primitive is hardware-module-only).
- `keystore/src/hbs-state.ts` — the **one-time-key state manager**: `OtsStateStore` + a `HbsKeyProvider`
  that orchestrates **reserve-before-sign** (durably burn the index, *then* delegate to an injected
  `HbsSignEngine`; a failed sign burns the leaf and never retries it → no reuse). `SoftwareOtsStateStore`
  is a dev/Local-Private reference, **hard-gated behind `allowUnsafeSoftwareState`**.
- `crypto/src/cnsa.ts` — the CNSA oracle now classifies **single-tree LMS/XMSS as conformant** and
  **HSS/XMSSᴹᵀ multi-tree as non-conformant**, so the single-tree rule is machine-checkable (C18).

## Consequences — honest caveats (binding)

- **The raw LMS/XMSS primitive is NOT built and must not be home-rolled.** It is adapter-provided
  (`HbsSignEngine`, the PKCS#11/HSM seam); `getCodeSigner` throws until a vetted FIPS 140-3 L3+ module
  is wired — exactly like FN-DSA-1024 and the KMS stubs.
- **The software state store is NOT a conformant signer** (verified by the adversarial pass): a
  consistent restore-from-backup moves the monotonic floor backward *undetectably*, and software fsync
  is unverifiable on virtual/network disks — either reuses an OTS index. The **only reuse-impossible**
  configuration is a hardware monotonic counter inside the FIPS boundary (the unbuilt adapter). The
  software path is dev/test only, gated, and refuses to construct without an explicit unsafe flag.
- **Redundancy differs from the rest of PolarSeek:** seal-the-seed is barred (it's the clone bug); HA is
  the SP 800-208 §7 way — multiple independent single-tree keys, verifiers accept any.
- A new gated suite/`getCodeSigner` path may be added (`PS-SIGN-LMS`, pending-standardization, never
  negotiated). FTO still required; grounded entirely in public guidance (no classified material).

## Credits

Gov-standards team (rank #3) + a dedicated design/verify workflow: `@noble`-absence and §8.1
hardware-only were verified against the installed package and the standard; the adversarial pass
confirmed the architectural call (keep HBS off seed-sealing) is correct and that the software path is
not reuse-safe — so it ships gated, not as a production signer.
