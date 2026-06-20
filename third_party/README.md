# Third-party license notices

PolarSeek's own source is licensed Apache-2.0 (see [`../LICENSE`](../LICENSE)).
It does **not** vendor third-party source into this tree — runtime dependencies
are consumed from npm/crates.

This directory holds the **upstream license texts** for the MIT-licensed
dependencies that are inlined into the standalone verifier produced by
`npm run bundle`, so that the redistributed artifact carries their required
copyright and permission notices (MIT) and PolarSeek satisfies Apache-2.0
section 4(d):

| File | Covers | Upstream © |
|------|--------|-----------|
| [`noble.LICENSE.txt`](noble.LICENSE.txt) | `@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum` | Paul Miller (2022, 2024) |
| [`cbor2.LICENSE.txt`](cbor2.LICENSE.txt) | `cbor2` | Joe Hildebrand (2023) |

The authoritative, version-pinned dependency inventory lives in
[`../conformance/src/supplychain.ts`](../conformance/src/supplychain.ts).
