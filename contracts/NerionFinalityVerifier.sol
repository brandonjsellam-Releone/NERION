// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// Reference contract — NOT YET COMPILED/DEPLOYED in this repo (Nerion is TypeScript/Rust; there is
// no Solidity toolchain here). It targets QRL Zond's QRVM (an EVM fork) + Hyperion (a post-quantum
// superset of Solidity that natively verifies lattice signatures; cf. EIP-8051 ML-DSA precompile).
//
// SOUND BY RECOMPUTATION: it reconstructs the validator-set id AND the signed attestation message
// ON-CHAIN (keccak256 fold, EVM-cheap — Nerion's EVM-native attestation profile, option B) from the
// trusted validator set + header, so a relayer cannot substitute either. The canonical reference is
// ledger/src/evmprofile.ts `verifyEvmFinality` (TESTED), which this MUST match byte-for-byte.
// See docs/research/interchain-qrl-zond.md.

pragma solidity ^0.8.24;

/// @notice ML-DSA-87 (FIPS-204) verification precompile exposed by QRVM / Hyperion. QRL Zond signs
/// its whole stack with ML-DSA-87 — the SAME scheme Nerion uses — so Nerion attestations verify
/// natively. The precompile address is Zond-network specific (EIP-8051-style); pin it at deployment.
interface IMLDSA87 {
    function verify(bytes calldata publicKey, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool ok);
}

/// @title NerionFinalityVerifier
/// @notice A block is "finalized" iff a >finalityNum/finalityDen STAKE quorum of DISTINCT trusted
///         validators signed the recomputed message with ML-DSA-87 — the post-quantum alternative to
///         trusted-multisig bridges (which lost ~$1B): the trust root is a transparency-logged stake
///         quorum the chain verifies itself.
contract NerionFinalityVerifier {
    /// @dev Zond-specific ML-DSA-87 precompile. Set the real address at deployment.
    IMLDSA87 public constant MLDSA87 = IMLDSA87(address(0x0000000000000000000000000000000000000900));

    bytes internal constant SET_TAG = "Nerion/evm-consensus-set/v1";
    bytes internal constant ATT_TAG = "Nerion/evm-attest/v1";

    struct Validator {
        bytes pubkey; // ML-DSA-87 public key; the `validators` array MUST be sorted ascending by pubkey
        uint256 stake;
        bytes vrfPubkey; // empty bytes if none
    }

    struct Attestation {
        bytes pubkey; // attestor's ML-DSA-87 public key (must be a set member)
        bytes signature; // ML-DSA-87 signature over the recomputed evm-profile message
    }

    /// @notice Recompute the keccak256 validator-set id (matches evmprofile.ts `evmSetId`).
    /// @dev Requires `validators` pre-sorted ascending by pubkey (the fold is order-dependent).
    function evmSetId(Validator[] calldata validators, uint256 epoch) public pure returns (bytes32) {
        bytes32 h = keccak256(SET_TAG);
        for (uint256 i = 0; i < validators.length; i++) {
            if (i > 0) require(_lt(validators[i - 1].pubkey, validators[i].pubkey), "unsorted/dup");
            bytes32 vrfH = keccak256(validators[i].vrfPubkey); // keccak256("") when none
            h = keccak256(abi.encodePacked(h, keccak256(validators[i].pubkey), validators[i].stake, vrfH));
        }
        return keccak256(abi.encodePacked(h, epoch));
    }

    /// @notice Recompute the message a validator signs (matches evmprofile.ts `evmAttestMessage`).
    function evmMessage(string calldata suite, uint256 height, bytes32 blockHash, bytes32 setId)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(keccak256(ATT_TAG), keccak256(bytes(suite)), height, blockHash, setId)
        );
    }

    /// @notice Verify Nerion finality. Reconstructs setId + message on-chain (no trusted relayer
    ///         input), verifies each ML-DSA-87 signature via the precompile, dedups distinct members,
    ///         and returns true iff the stake quorum is met.
    function verifyFinality(
        Validator[] calldata validators,
        Attestation[] calldata attestations,
        string calldata suite,
        uint256 height,
        bytes32 blockHash,
        uint256 epoch,
        uint256 finalityNum,
        uint256 finalityDen
    ) external view returns (bool finalized) {
        require(finalityNum >= 1 && finalityDen >= 1 && finalityNum <= finalityDen, "bad threshold");

        bytes32 setId = evmSetId(validators, epoch);
        bytes memory message = abi.encodePacked(evmMessage(suite, height, blockHash, setId));

        uint256 total = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            total += validators[i].stake;
        }
        require(total > 0, "empty set");

        uint256 attesting = 0;
        for (uint256 a = 0; a < attestations.length; a++) {
            bytes calldata pk = attestations[a].pubkey;

            // Dedup: count each distinct validator at most once.
            bool seen = false;
            for (uint256 p = 0; p < a; p++) {
                if (keccak256(attestations[p].pubkey) == keccak256(pk)) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;

            // Resolve to a set member + its stake.
            uint256 stake = 0;
            for (uint256 v = 0; v < validators.length; v++) {
                if (keccak256(validators[v].pubkey) == keccak256(pk)) {
                    stake = validators[v].stake;
                    break;
                }
            }
            if (stake == 0) continue;

            // Native post-quantum verification over the RECOMPUTED message.
            if (!MLDSA87.verify(pk, message, attestations[a].signature)) continue;

            attesting += stake;
        }

        finalized = (attesting * finalityDen >= finalityNum * total);
    }

    /// @dev Lexicographic byte-string less-than (for the ascending-pubkey sortedness check).
    function _lt(bytes calldata x, bytes calldata y) internal pure returns (bool) {
        uint256 n = x.length < y.length ? x.length : y.length;
        for (uint256 i = 0; i < n; i++) {
            if (x[i] != y[i]) return x[i] < y[i];
        }
        return x.length < y.length;
    }
}

// INTEGRATION NOTES:
//   1. Cap `validators.length` / `attestations.length` at the call site (decode-side DoS).
//   2. The ML-DSA-87 precompile address is Zond-network specific — pin it from the live spec.
//   3. Validators co-sign the evm-profile (evmprofile.ts `signEvmAttestation`) alongside consensus
//      when interchain export is wanted (opt-in); the native dCBOR/SHAKE256 consensus path is
//      unchanged. The keccak fold here is byte-identical to evmprofile.ts (the tested TS reference).
