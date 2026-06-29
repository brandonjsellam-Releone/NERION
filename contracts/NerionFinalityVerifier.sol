// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// Reference contract — NOT YET COMPILED/DEPLOYED in this repo (Nerion is TypeScript/Rust; there is
// no Solidity toolchain here). It targets QRL Zond's QRVM (an EVM fork) + Hyperion (a post-quantum
// superset of Solidity that natively verifies lattice signatures; cf. EIP-8051 ML-DSA precompile).
// It is the on-chain "destination" of the Nerion interchain: see docs/research/interchain-qrl-zond.md
// and ledger/src/evm.ts (the off-chain encoder that produces this contract's input).

pragma solidity ^0.8.24;

/// @notice ML-DSA-87 (FIPS-204) signature-verification precompile exposed by QRVM / Hyperion.
/// @dev On QRL Zond the account/consensus signature scheme is ALSO ML-DSA-87, so Nerion's existing
///      attestations verify natively — no scheme translation. The precompile address is Zond-network
///      specific (EIP-8051-style); pin it from the Zond spec at deployment. Placeholder below.
interface IMLDSA87 {
    function verify(bytes calldata publicKey, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool ok);
}

/// @title NerionFinalityVerifier
/// @notice Verifies a Nerion portable finality proof on-chain: a block is "finalized" iff a >2/3
///         STAKE quorum of the trusted validator set signed it with ML-DSA-87. This is the
///         post-quantum alternative to trusted-multisig bridges (which lost ~$1B): the trust root is
///         a transparency-logged stake quorum verified by the chain itself, not a custodial committee.
contract NerionFinalityVerifier {
    /// @dev Zond-specific ML-DSA-87 precompile. Set the real address at deployment.
    IMLDSA87 public constant MLDSA87 = IMLDSA87(address(0x0000000000000000000000000000000000000900));

    struct Validator {
        bytes pubkey; // ML-DSA-87 public key
        uint256 stake; // non-negative stake weight
    }

    struct Attestation {
        bytes pubkey; // attestor's ML-DSA-87 public key (must be a set member)
        bytes message; // the exact bytes Nerion signed (relayer-provided; see SECURITY note)
        bytes signature; // ML-DSA-87 signature over `message`
    }

    /// @notice Verify a Nerion finality proof. Returns true iff a >finalityNum/finalityDen stake
    ///         quorum of DISTINCT set members produced a valid ML-DSA-87 signature for this block.
    /// @param validators the verifier's OWN trusted validator set (the trust anchor).
    /// @param attestations the attestations carried by the portable proof.
    /// @param expectedMessage the canonical attestation message the contract REQUIRES every valid
    ///        attestation to equal (see SECURITY). The caller computes it; this contract enforces
    ///        byte-equality so a relayer cannot mix messages.
    /// @param finalityNum,finalityDen the finality fraction (default 2/3).
    function verifyFinality(
        Validator[] calldata validators,
        Attestation[] calldata attestations,
        bytes calldata expectedMessage,
        uint256 finalityNum,
        uint256 finalityDen
    ) external view returns (bool finalized) {
        require(finalityNum >= 1 && finalityDen >= 1 && finalityNum <= finalityDen, "bad threshold");

        uint256 total = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            total += validators[i].stake;
        }
        require(total > 0, "empty set");

        uint256 attesting = 0;
        // Distinct-attestor accumulation. O(n^2) membership/dedup is fine for the small validator
        // sets a light-client proof carries; cap the input length at the call site.
        for (uint256 a = 0; a < attestations.length; a++) {
            Attestation calldata at = attestations[a];

            // Every counted attestation must sign the SAME canonical message (binds height+hash+setId).
            if (keccak256(at.message) != keccak256(expectedMessage)) continue;

            // Resolve the attestor to a set member + its stake; skip non-members.
            uint256 stake = 0;
            bool member = false;
            for (uint256 v = 0; v < validators.length; v++) {
                if (keccak256(validators[v].pubkey) == keccak256(at.pubkey)) {
                    stake = validators[v].stake;
                    member = true;
                    break;
                }
            }
            if (!member || stake == 0) continue;

            // Dedup: count each distinct validator at most once (no stake inflation by replay).
            bool seen = false;
            for (uint256 p = 0; p < a; p++) {
                if (keccak256(attestations[p].pubkey) == keccak256(at.pubkey)) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;

            // Native post-quantum verification (QRVM/Hyperion ML-DSA-87 precompile).
            if (!MLDSA87.verify(at.pubkey, at.message, at.signature)) continue;

            attesting += stake;
        }

        // Exact >=2/3 cross-multiply (no division).
        finalized = (attesting * finalityDen >= finalityNum * total);
    }
}

// SECURITY / INTEGRATION NOTES (read before deploying):
//   1. `expectedMessage` and the `setId` it embeds MUST be recomputed BY THE VERIFIER, not trusted
//      from the relayer, or a relayer could substitute a different validator set. Two sound options:
//      (A) port Nerion's dCBOR + SHAKE256 `consensusSetId`/`attestMessage` faithfully into Hyperion
//          and recompute `expectedMessage` here from (suite, height, blockHash, validators, epoch);
//      (B) add a Nerion EVM-native attestation profile (keccak/abi.encode) signed alongside the
//          dCBOR one, so this contract recomputes cheaply. Until then this reference accepts the
//          message as a parameter and only enforces all attestations agree on it (option-A/B is the
//          remaining integration work). docs/research/interchain-qrl-zond.md tracks the decision.
//   2. Cap `attestations.length` and `validators.length` at the call site (decode-side DoS).
//   3. The ML-DSA-87 precompile address is Zond-network specific — pin it from the live spec.
