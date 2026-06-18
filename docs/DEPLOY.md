# PolarSeek — Running & Deploying (Local/Private)

> **Deployment maturity (honest):** this is **Local/Private dev mode** — runnable,
> fully tested, and good for design-partner pilots and internal evaluation. It is
> **not** production-hardened. Production additionally requires: the Rust hot-path
> (latency + constant-time), real TEE attestation hardware (TDX/SEV-SNP/CCA),
> HSM/KMS-held keys, multi-operator log mirroring + gossip, an external security
> audit, and a patent-counsel FTO opinion ([FTO_TODO.md](./FTO_TODO.md)). See the
> progressive-decentralization ladder in the build spec: Local/Private →
> Consortium → Public.

## Prerequisites

- Node ≥ 20 (built/tested on Node 24), npm. No Rust/Go needed for this mode.

## Quick start

```bash
npm ci                 # install (from the committed lockfile)
npm run gate           # clean-room lint + prettier + tsc + 108 tests
npm run demo           # end-to-end T2 governed-payment trace (in-process)
```

## Build + the standalone external verifier

```bash
npm run build          # tsc -> dist/
npm run bundle         # run a T2 admission, write polarseek-receipt-bundle.json
npm run verify:cli     # INDEPENDENTLY verify that bundle (sig + log inclusion)
# verify a specific file:
node tools/verify-receipt.mjs path/to/bundle.json
```

`verify:cli` trusts **only** the issuer public key and the gossiped log root
embedded in the bundle — never the issuer's or the log operator's honesty. It
re-derives the Merkle root from the inclusion proof and verifies the ML-DSA-87
signature. Tampering with any field (effect, tier, commitments, proof) makes it
exit non-zero with a reason.

## Embedding (library) — admit an agent action

```ts
import { PolarSeekNode, verifyPermitForAction } from './planes/src/index.js'
import { TransparencyLog } from './translog/src/index.js'
import { DEFAULT_POLICY } from './kernel/src/index.js'

const node = new PolarSeekNode({
  suite, policy: DEFAULT_POLICY, trustedRoots, issuer, log: new TransparencyLog(),
  jurisdiction: 'US', permitTtlSeconds: 30,
})
const out = node.admit({ intent, capabilities, session, audience, now, observedAggregate })
// Plane 1: out.permit is bound to {action, audience, session, exp}.
// The resource re-checks before executing:
const ok = verifyPermitForAction(out.permit!, session.sessionKey, { audience, intent, now }).ok
// Plane 2: out.receipt is anchored at out.inclusion / out.logRoot for audit.
```

## What you can show a reviewer today

- `npm run demo` — a governed Tier-2 payment: intent → admission → bound permit →
  PQ receipt → transparency-log anchoring → independent verify (PASS), + a DENY.
- `npm run verify:cli` — a third party verifying a receipt with zero trust in the
  operator; tamper the JSON and watch it fail.
- `kernel/spec/PolarSeekKernel.tla` — the formal safety model (property-tested).
- `docs/CLEANROOM.md` + `npm run lint:cleanroom` — the CI-enforced non-infringement firewall.
