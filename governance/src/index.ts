// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/governance — M-of-N quorum, revocation, local kill switch.
 */

export type { ProposalKind, Proposal, Quorum, Approval, EnactmentResult } from './types.js'
export {
  proposalId,
  approve,
  verifyApproval,
  enact,
  RevocationRegistry,
  LocalKillSwitch,
} from './quorum.js'
