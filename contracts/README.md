<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nerion interchain contracts (reference)

On-chain verification of **Nerion finality** on an EVM chain — primarily **QRL Zond** (QRVM +
Hyperion), which signs its whole stack with **ML-DSA-87 (FIPS-204)**, the *same* scheme Nerion uses,
so a contract verifies Nerion attestations **natively** with no scheme translation. Design +
rationale: [`docs/research/interchain-qrl-zond.md`](../docs/research/interchain-qrl-zond.md).

> **Status: reference — NOT compiled, tested, deployed, or audited in this repo.** Nerion is a
> TypeScript/Rust project with no Solidity toolchain. These files are the destination-side reference
> + the cross-implementation conformance harness.

## Files
- **`NerionFinalityVerifier.sol`** — verifies a ≥2/3 ML-DSA-87 stake quorum over the block, by
  **recomputing** the validator-set id + signed message on-chain (keccak256 fold) so a relayer can
  substitute neither, and **binding the destination** (`require(chainId == block.chainid)`,
  `require(verifier == address(this))`) so a finality proof can not be replayed on another chain or
  deployment. Caps `validators.length` / `attestations.length` (decode-side DoS). It also exposes
  **`verifyEquivocation`** — accountable slashing evidence: a validator that co-signed VALID
  attestations for two DISTINCT blocks at the SAME height is caught (matches `evmprofile.ts`
  `verifyEvmEquivocationProof`, LEDGER-EVM-ACCT-001). The post-quantum alternative to trusted-multisig
  bridges.
- **`test/NerionFinalityVerifier.t.sol`** — Foundry test asserting the on-chain encoding matches the
  golden vectors.
- **`test/evm-profile-vectors.json`** — golden cross-implementation vectors.

## Cross-implementation lock (the important part)
The `keccak256` fold encoding is the only place a TS↔Solidity bug could hide, so it is pinned by
**one set of golden vectors checked by both sides**:
- TypeScript: [`ledger/src/evmprofile.ts`](../ledger/src/evmprofile.ts) (the tested reference) →
  asserted against the vectors by `ledger/test/evmprofile-vectors.test.ts`.
- Solidity: `NerionFinalityVerifier.{evmSetId,evmMessage}` → asserted against the *same* vectors by
  `test/NerionFinalityVerifier.t.sol`.

If both pass, on-chain verification matches off-chain byte-for-byte.

## Build / test (requires Foundry + a QRL Zond / Hyperion toolchain)
```sh
forge install foundry-rs/forge-std   # provides forge-std/Test.sol
forge build
forge test
```

## Deployment notes
- Pin the **ML-DSA-87 precompile address** from the live QRL Zond spec (placeholder in the contract).
- Cap `validators.length` / `attestations.length` at the call site (decode-side DoS).
- Validators co-sign the EVM profile (`evmprofile.ts` `signEvmAttestation`) alongside consensus when
  interchain export is wanted (opt-in; the native dCBOR/SHAKE256 consensus path is unchanged).
