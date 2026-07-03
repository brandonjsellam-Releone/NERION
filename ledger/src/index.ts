// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/ledger — pure-PoS, stake-finalized, PQ light-client-verifiable.
 */

export type {
  Validator,
  ValidatorSet,
  BlockHeader,
  Block,
  Attestation,
  TimeoutVote,
  ViewChangeCert,
  FinalizedBlock,
  LightClientVerdict,
} from './types.js'
export {
  totalStake,
  totalStakeBig,
  stakeOf,
  selectLeader,
  canonicalRound,
  safeStake,
  isWellFormedStakeSet,
  consensusSetId,
} from './sortition.js'
export { Ledger, LedgerError, blockHash, verifyFinalized, GENESIS_PREV } from './chain.js'
export type { VerifyOpts } from './chain.js'
export { detectEquivocations, verifyEquivocationProof, slash } from './equivocation.js'
export type { EquivocationProof } from './equivocation.js'
export { GossipBus, GossipNode } from './gossip.js'
export type { GossipMessage } from './gossip.js'
export { prove, verify, vrfPublicKey, VrfError } from './vrf.js'
export type { VrfOutput } from './vrf.js'
export {
  vrfAlpha,
  vrfLeaderEligible,
  vrfPriority,
  viewChangeMessage,
  verifyViewChangeCert,
} from './leader.js'
export {
  exportFinalityProof,
  verifyPortableFinality,
  serializeFinalityProof,
  deserializeFinalityProof,
} from './portable.js'
export type { PortableFinalityProof } from './portable.js'
export { finalityProofToEvmInput } from './evm.js'
export type { EvmFinalityInput, EvmValidator, EvmAttestation } from './evm.js'
export { evmSetId, evmAttestMessage, signEvmAttestation, verifyEvmFinality } from './evmprofile.js'
export type { EvmSignedAttestation, EvmFinalityVerdict, EvmTarget } from './evmprofile.js'
