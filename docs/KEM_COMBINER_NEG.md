# PQC-2 — hybrid-KEM combiner negative tests (truncation / extension)

> Status: research-engineering. UNAUDITED, pre-FTO. Additive — **tests only**, no crypto behaviour,
> no wire / KAT / `Ps1` change. Branch-only.

## What

Nerion registers only **hybrid** KEMs — a classical ECDH leg combined with an ML-KEM leg via a vetted
KDF combiner (`XWING-MLKEM768-X25519`, `MLKEM1024-P384`). `kem.test.ts` already covers the **1-byte
tamper** and **wrong-key** classes (implicit rejection). The class that was **not** exercised is a
**length-altering** mutation of the hybrid ciphertext — dropping or appending bytes, which can
mis-split the combiner's two legs.

`crypto/test/kem-combiner-neg.property.test.ts` pins that class fail-closed for every implemented
hybrid KEM:

- **Truncations** (drop last / half / first byte, tiny prefix, empty) never recover the shared secret.
- **Extensions** (append `0x00` / `0xff` / 64 zero bytes) never recover the shared secret.
- **Property** (fixed seed, 200 runs): *any* length-altered ciphertext (`len ≠ original`) fails
  closed — `decapsulate` either throws on the length/format mismatch or returns a different,
  implicitly-rejected secret.
- **Regression pin**: the honest round-trip recovers, and the combiner ciphertext length is stable
  across encapsulations — so a future `@noble` bump that silently changes the combiner format is
  visible.

"Fail-closed" treats both a thrown length error and a non-matching secret as rejection.

## Why it is beyond the prior bar

The existing tests flip a byte; they do not change the ciphertext *length*, so a combiner that
mis-handles a truncated/extended ciphertext (leg-splitting confusion) would pass them. This adds the
missing class as a re-runnable, seeded negative test across both hybrid KEMs.

## Scope / honesty

- Marked **INCREMENTAL** honestly: the 1-byte-tamper and wrong-key classes already pass as live tests;
  the genuinely-new coverage is the truncation/extension class + the length-stability regression pin.
- Tests only — no `@noble` primitive is modified; this exercises shipped behaviour. The result is a
  coverage/robustness gain, **not** a security or audited claim. UNAUDITED / pre-FTO.
- A cross-implementation (Rust KEM) negative KAT is out of scope — no Rust KEM path exists yet.

*Origin: Beyond-Apex Frontier item PQC-2 (see [BEYOND_APEX_FRONTIER.md](./BEYOND_APEX_FRONTIER.md)).*
