# crypto/ — PolarSeek post-quantum, crypto-agile primitives

P0 reference implementation in TypeScript over audited `@noble` libraries. Every
signed/encrypted object carries a negotiable `SuiteID`; no algorithm is
hard-coded into protocol logic. The Rust hot-path implementation will conform to
this same contract (see [../docs/adr/ADR-0002-ts-reference-and-kem-pairing.md](../docs/adr/ADR-0002-ts-reference-and-kem-pairing.md)).

## Modules (`src/`)

| File | Purpose |
|---|---|
| `types.ts` | Agility interfaces: `Kem`, `SignatureScheme`, `Aead`, `Mac`, `HashFn`, `Suite`. |
| `suites.ts` | `SuiteID` registry, `negotiate()`, `kemFor()`/`signerFor()`. |
| `kem.ts` | Hybrid KEMs: X-Wing (X25519+ML-KEM-768), ML-KEM-1024+P-384. HQC stub. |
| `sign.ts` | ML-DSA-87, SLH-DSA-SHAKE-256f. Falcon/FN-DSA stub (not load-bearing). |
| `symmetric.ts` | AES-256-GCM, HMAC-SHA-384, SHA3-256/SHAKE256, CSPRNG, constant-time compare. |
| `cbor.ts` | Deterministic (dCBOR) canonical encoding — the bytes we hash/sign. |
| `envelope.ts` | SuiteID-bound signed envelopes; hot-path PermitTokens (HMAC). |
| `errors.ts` | Stable error codes; `NotImplementedError` carries a `CONNECT` pointer. |

## Suites

| SuiteID | Tier | KEM | Signature |
|---|---|---|---|
| `PS-1` | general / CNSA-transition (Cat-3) | X-Wing (X25519+ML-KEM-768) | ML-DSA-87 |
| `PS-5` | regulated CNSA 2.0 (Cat-5) | ML-KEM-1024 + ECDH P-384 | ML-DSA-87 |
| `PS-5-HQC` | pending (FIPS 207) | HQC-256 | ML-DSA-87 |
| `PS-5-FN` | not-load-bearing (FIPS 206) | ML-KEM-1024+P-384 | FN-DSA-1024 |

## Example

```ts
import { negotiate, signerFor, signEnvelope, verifyEnvelope, SUITE_IDS } from './src/index.js'

const suite = negotiate([SUITE_IDS.PS_1, SUITE_IDS.PS_5], [SUITE_IDS.PS_5]) // -> 'PS-5'
const { publicKey, secretKey } = signerFor(suite).keygen()
const env = signEnvelope({ intent: 'transfer', amount: 5 }, suite, secretKey, 'receipt')
verifyEnvelope(env, publicKey) // true; tampering or a SuiteID downgrade -> false
```

## Tests & vectors

- `test/` — KATs, hybrid round-trips, tamper/wrong-key rejection, AEAD/MAC,
  canonical-CBOR determinism, suite negotiation, envelope + PermitToken.
- `vectors/deterministic-kat.json` — committed regression vectors; regenerate
  with `node crypto/vectors/_gen.mjs`. CI fails on drift.
- **TODO:** wire official NIST ACVP KAT vectors (tracked in `../docs/STATUS.md`).

Run: `npm run gate` (from repo root).
