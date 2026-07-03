// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// Foundry cross-implementation test — NOT RUN in this repo (no Solidity toolchain here). When
// compiled on a Foundry/Hyperion toolchain it asserts the on-chain encoding (evmSetId / evmMessage)
// reproduces the SAME golden vectors the TypeScript reference is locked to
// (contracts/test/evm-profile-vectors.json, enforced by ledger/test/evmprofile-vectors.test.ts).
// If TS and Solidity agree on these, on-chain verification matches off-chain byte-for-byte.

pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NerionFinalityVerifier} from "../NerionFinalityVerifier.sol";

contract NerionFinalityVerifierTest is Test {
    NerionFinalityVerifier internal v;

    function setUp() public {
        v = new NerionFinalityVerifier();
    }

    // Vector: setA = [aa/1, bb/2, cc/3], sorted ascending by pubkey.
    function _setA() internal pure returns (NerionFinalityVerifier.Validator[] memory vs) {
        vs = new NerionFinalityVerifier.Validator[](3);
        vs[0] = NerionFinalityVerifier.Validator(hex"aa", 1, hex"");
        vs[1] = NerionFinalityVerifier.Validator(hex"bb", 2, hex"");
        vs[2] = NerionFinalityVerifier.Validator(hex"cc", 3, hex"");
    }

    function test_evmSetId_setA_epoch0() public view {
        assertEq(
            v.evmSetId(_setA(), 0),
            bytes32(0xf36be9d1442b4257844332f3b3fc593ebb6cbed5e529ef87ef8dc9e811480e9a)
        );
    }

    function test_evmSetId_setA_epoch5() public view {
        assertEq(
            v.evmSetId(_setA(), 5),
            bytes32(0x0da6a1e08739d5d2b0fc4792e46a7f239532290718b695ee5fa3325075543210)
        );
    }

    function test_evmSetId_withVrf() public view {
        NerionFinalityVerifier.Validator[] memory vs = new NerionFinalityVerifier.Validator[](2);
        vs[0] = NerionFinalityVerifier.Validator(hex"aa", 1, hex"dd"); // vrfPubkey = dd
        vs[1] = NerionFinalityVerifier.Validator(hex"bb", 2, hex""); // no vrf -> keccak256("")
        assertEq(
            v.evmSetId(vs, 0),
            bytes32(0x9e19f696615dfb6f70a6a7170fc5eb3098d8b4a091a8c54f26716e2dff310ebc)
        );
    }

    function test_evmMessage() public view {
        bytes32 setId = bytes32(0xf36be9d1442b4257844332f3b3fc593ebb6cbed5e529ef87ef8dc9e811480e9a);
        bytes32 blockHash = bytes32(
            0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
        );
        // Destination-bound: chainId 8888, verifier 0xc0..c0 (synthetic, matches the golden vector).
        assertEq(
            v.evmMessage(
                "PS-5",
                8888,
                address(0xc0C0c0C0C0c0c0C0C0C0c0c0c0c0C0c0c0C0C0c0),
                7,
                blockHash,
                setId
            ),
            bytes32(0x7f52021806c7ea8153ed2785a506d345830019e4db5ebecc274fe677c9d90f7c)
        );
    }

    // Rejects an unsorted / duplicate validator set (the fold is order-dependent).
    function test_evmSetId_rejectsUnsorted() public {
        NerionFinalityVerifier.Validator[] memory vs = new NerionFinalityVerifier.Validator[](2);
        vs[0] = NerionFinalityVerifier.Validator(hex"cc", 1, hex"");
        vs[1] = NerionFinalityVerifier.Validator(hex"aa", 1, hex"");
        vm.expectRevert(bytes("unsorted/dup"));
        v.evmSetId(vs, 0);
    }
}
