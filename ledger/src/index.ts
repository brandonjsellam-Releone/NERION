/**
 * @polarseek/ledger — pure-PoS, stake-finalized, PQ light-client-verifiable.
 */

export type {
  Validator,
  ValidatorSet,
  BlockHeader,
  Block,
  Attestation,
  FinalizedBlock,
  LightClientVerdict,
} from './types.js'
export { totalStake, stakeOf, selectLeader, canonicalRound } from './sortition.js'
export { Ledger, LedgerError, blockHash, verifyFinalized, GENESIS_PREV } from './chain.js'
export type { VerifyOpts } from './chain.js'
export { detectEquivocations, verifyEquivocationProof, slash } from './equivocation.js'
export type { EquivocationProof } from './equivocation.js'
