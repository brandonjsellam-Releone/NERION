// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// Reference contract — NOT YET COMPILED/DEPLOYED in this repo (Nerion is TypeScript/Rust; there is
// no Solidity toolchain here). It targets QRL Zond's QRVM (an EVM fork) + Hyperion (a post-quantum
// superset of Solidity that natively verifies lattice signatures; cf. EIP-8051 ML-DSA precompile).
//
// SOUND BY RECOMPUTATION + DESTINATION BINDING: it reconstructs the validator-set id AND the signed
// attestation message ON-CHAIN (keccak256 fold, EVM-cheap — Nerion's EVM-native attestation profile,
// option B) from the trusted validator set + header, so a relayer cannot substitute either; and the
// signed message binds the DESTINATION (chainId + verifier address), enforced here against
// `block.chainid` + `address(this)`, so a finality proof for one chain/deployment can NOT be
// replayed on another (cross-chain replay). The canonical reference is ledger/src/evmprofile.ts
// `verifyEvmFinality` (TESTED), which this MUST match byte-for-byte. See
// docs/research/interchain-qrl-zond.md.

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

    /// @dev Decode-side DoS caps (mirror evmprofile.ts). Bound work before the per-signature verify.
    uint256 internal constant MAX_VALIDATORS = 4096;
    uint256 internal constant MAX_ATTESTATIONS = 8192;

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
    /// @dev Binds the destination `chainId` + `verifier` address so the proof is not replayable on
    ///      another chain/deployment. `pure` (reproducible from params) so the golden cross-impl
    ///      vectors pin the encoding; `verifyFinality` enforces chainId/verifier == the live chain.
    function evmMessage(
        string calldata suite,
        uint256 chainId,
        address verifier,
        uint256 height,
        bytes32 blockHash,
        bytes32 setId
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                keccak256(ATT_TAG),
                keccak256(bytes(suite)),
                chainId,
                verifier,
                height,
                blockHash,
                setId
            )
        );
    }

    /// @notice Verify Nerion finality. Reconstructs setId + message on-chain (no trusted relayer
    ///         input), verifies each ML-DSA-87 signature via the precompile, dedups distinct members,
    ///         and returns true iff the stake quorum is met.
    function verifyFinality(
        Validator[] calldata validators,
        Attestation[] calldata attestations,
        string calldata suite,
        uint256 chainId,
        address verifier,
        uint256 height,
        bytes32 blockHash,
        uint256 epoch,
        uint256 finalityNum,
        uint256 finalityDen
    ) external view returns (bool finalized) {
        require(finalityNum >= 1 && finalityDen >= 1 && finalityNum <= finalityDen, "bad threshold");
        // Destination binding: the proof is only valid for THIS chain and THIS verifier deployment.
        require(chainId == block.chainid, "wrong chain");
        require(verifier == address(this), "wrong verifier");
        // Decode-side DoS caps.
        require(validators.length <= MAX_VALIDATORS, "too many validators");
        require(attestations.length <= MAX_ATTESTATIONS, "too many attestations");

        bytes32 setId = evmSetId(validators, epoch);
        bytes memory message =
            abi.encodePacked(evmMessage(suite, chainId, verifier, height, blockHash, setId));

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

    /// @notice Verify a slashable EVM-profile equivocation proof (matches evmprofile.ts
    ///         `verifyEvmEquivocationProof` — LEDGER-EVM-ACCT-001). Returns true iff `validator` is a
    ///         set member with stake AND validly signed the recomputed messages for BOTH distinct
    ///         blocks at the SAME height. Same-height double-signing is the offense; honest
    ///         one-block-per-height behavior across DIFFERENT heights is NOT (each call pins one
    ///         height), matching the native equivocation semantics. The messages are RECOMPUTED from
    ///         the trusted set + destination (never a relayer), and the destination is pinned to this
    ///         chain/verifier, so a proof cannot be forged, replayed cross-chain, or (because setId
    ///         folds the epoch) reused across epochs.
    /// @dev The CALLER slashes on a true return; this contract only adjudicates the evidence.
    function verifyEquivocation(
        Validator[] calldata validators,
        bytes calldata validator,
        string calldata suite,
        uint256 chainId,
        address verifier,
        uint256 height,
        bytes32 blockHashA,
        bytes calldata sigA,
        bytes32 blockHashB,
        bytes calldata sigB,
        uint256 epoch
    ) external view returns (bool slashable) {
        require(chainId == block.chainid, "wrong chain");
        require(verifier == address(this), "wrong verifier");
        require(validators.length <= MAX_VALIDATORS, "too many validators");
        if (blockHashA == blockHashB) return false; // same block is not equivocation

        // The named validator must be a set member with positive stake.
        uint256 stake = 0;
        for (uint256 v = 0; v < validators.length; v++) {
            if (keccak256(validators[v].pubkey) == keccak256(validator)) {
                stake = validators[v].stake;
                break;
            }
        }
        if (stake == 0) return false;

        bytes32 setId = evmSetId(validators, epoch);
        bytes memory msgA =
            abi.encodePacked(evmMessage(suite, chainId, verifier, height, blockHashA, setId));
        bytes memory msgB =
            abi.encodePacked(evmMessage(suite, chainId, verifier, height, blockHashB, setId));

        // BOTH signatures must verify under the validator's key over the two same-height messages.
        slashable =
            MLDSA87.verify(validator, msgA, sigA) && MLDSA87.verify(validator, msgB, sigB);
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
//   1. `validators.length` / `attestations.length` are capped in-contract (MAX_VALIDATORS /
//      MAX_ATTESTATIONS), matching evmprofile.ts — decode-side DoS bound before any verify.
//   2. The ML-DSA-87 precompile address is Zond-network specific — pin it from the live spec.
//   3. PRECOMPILE MESSAGE FRAMING (UNPINNED — verify before deploy): `evmMessage` returns a bare
//      32-byte keccak digest. noble's `ml_dsa87.sign` (the TS reference) is PURE ML-DSA (FIPS 204
//      §5.2): it internally frames the message as `0x00 ‖ len(ctx)=0x00 ‖ msg` before computing mu.
//      This contract must pass the precompile EXACTLY the message the TS signer signed. Confirm
//      whether IMLDSA87.verify expects the bare 32-byte digest (and applies the domain prefix
//      itself) or a pre-framed input, and pin a cross-impl KAT accordingly. A mismatch fails closed
//      (every attestation rejected), not open — but it must be reconciled for the profile to work.
//   4. Validators co-sign the evm-profile (evmprofile.ts `signEvmAttestation`) alongside consensus
//      when interchain export is wanted (opt-in); the native dCBOR/SHAKE256 consensus path is
//      unchanged. The keccak fold here is byte-identical to evmprofile.ts (the tested TS reference),
//      and the signed message binds chainId + verifier so a proof is not replayable cross-chain.
