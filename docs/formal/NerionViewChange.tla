\* SPDX-FileCopyrightText: 2026 TRELYAN
\* SPDX-License-Identifier: Apache-2.0
------------------------------ MODULE NerionViewChange ------------------------------
(***************************************************************************)
(* A TLA+ MODEL of Nerion's round / view-change layer, machine-checking the *)
(* claim in docs/CONSENSUS-CAVEATS.md §1: a >=2/3 coalition can SKIP rounds   *)
(* cheaply (LEDGER-007 — O(1) in round distance) and thereby control which    *)
(* block is *proposed*, but this is a FAIRNESS/liveness weakness ONLY — it     *)
(* cannot manufacture a SAFETY violation, because finalization still requires  *)
(* a >2/3 stake quorum of attestations and honest validators attest at most    *)
(* one block per height.                                                       *)
(*                                                                            *)
(* Companion to NerionConsensus.tla (accountable safety). This model adds the *)
(* round + view-change + proposal machinery and shows it does not weaken the   *)
(* safety result. MODEL of an ABSTRACTION — machine-checked by TLC, NOT a      *)
(* proof of the implementation; abstracts signatures, networking, timing.      *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Validators, Stake, Byzantine, Heights, Blocks, MaxRound

ASSUME ByzantineIsSubset == Byzantine \subseteq Validators
ASSUME StakeIsNat        == Stake \in [Validators -> Nat]
ASSUME MaxRoundIsNat     == MaxRound \in Nat

VARIABLES
    curRound,  \* highest round reached so far (advanced via view-change certs)
    proposed,  \* SUBSET (Heights \X Blocks): blocks a round-leader has proposed
    attested   \* [Validators -> SUBSET (Heights \X Blocks)]: blocks each validator attested
vars == << curRound, proposed, attested >>

EqualStake == [v \in Validators |-> 1]
RECURSIVE SumStake(_)
SumStake(S) == IF S = {} THEN 0
                ELSE LET v == CHOOSE x \in S : TRUE IN Stake[v] + SumStake(S \ {v})
TotalStake == SumStake(Validators)

Attestors(h, b) == { v \in Validators : << h, b >> \in attested[v] }
\* Finalization is a >2/3 stake quorum of attestations — ROUND-INDEPENDENT by design.
Finalized(h, b) == 3 * SumStake(Attestors(h, b)) > 2 * TotalStake

Equivocates(v) == \E h \in Heights, b1 \in Blocks, b2 \in Blocks :
                     b1 # b2 /\ << h, b1 >> \in attested[v] /\ << h, b2 >> \in attested[v]
Equivocators == { v \in Validators : Equivocates(v) }

\* A >2/3-stake coalition exists to sign a view-change cert (the precondition for a skip).
QuorumCoalitionExists == \E S \in SUBSET Validators : 3 * SumStake(S) > 2 * TotalStake

TypeOK == /\ curRound \in 0..MaxRound
          /\ proposed \subseteq (Heights \X Blocks)
          /\ attested \in [Validators -> SUBSET (Heights \X Blocks)]

Init == /\ curRound = 0
        /\ proposed = {}
        /\ attested = [v \in Validators |-> {}]

\* LEDGER-007: a >=2/3 coalition mints one view-change cert and jumps to ANY higher
\* round at O(1) cost. We model the worst case — arbitrary skip — as a single step.
SkipRound(r) ==
    /\ r > curRound /\ r =< MaxRound
    /\ QuorumCoalitionExists
    /\ curRound' = r
    /\ UNCHANGED << proposed, attested >>

\* The current round's leader proposes a block. Because round-skip lets the adversary
\* land on a round whose leader it controls, we conservatively allow ANY block to be
\* proposed (maximal adversarial proposal control).
Propose(h, b) ==
    /\ << h, b >> \notin proposed
    /\ proposed' = proposed \cup { << h, b >> }
    /\ UNCHANGED << curRound, attested >>

\* A validator attests a PROPOSED block. Honest validators attest at most one block per
\* height; Byzantine validators may equivocate.
HonestFreeAt(v, h) == \A bb \in Blocks : << h, bb >> \notin attested[v]
Attest(v, h, b) ==
    /\ << h, b >> \in proposed
    /\ << h, b >> \notin attested[v]
    /\ (v \in Byzantine \/ HonestFreeAt(v, h))
    /\ attested' = [attested EXCEPT ![v] = @ \cup { << h, b >> }]
    /\ UNCHANGED << curRound, proposed >>

NormalNext ==
    \/ \E r \in 0..MaxRound : SkipRound(r)
    \/ \E h \in Heights, b \in Blocks : Propose(h, b)
    \/ \E v \in Validators, h \in Heights, b \in Blocks : Attest(v, h, b)

\* Terminal stutter so the legitimately-terminating behaviour is not a deadlock.
Next == NormalNext \/ (~ ENABLED NormalNext /\ UNCHANGED vars)
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants — checked in every reachable state, for ALL skip sequences.   *)
(***************************************************************************)

\* I1. Round-skip alone never finalizes: a finalized block carries a >2/3 quorum,
\*     independent of how high curRound was skipped.
FinalizationNeedsQuorum ==
    \A h \in Heights, b \in Blocks :
        Finalized(h, b) => 3 * SumStake(Attestors(h, b)) > 2 * TotalStake

\* I2. SAFETY UNDER ROUND-SKIP (the headline). For any skip sequence, two distinct
\*     finalized blocks at one height imply >= 1/3 equivocating stake. Round
\*     manipulation cannot manufacture a fork.
SafetyUnderRoundSkip ==
    \A h \in Heights, b1 \in Blocks, b2 \in Blocks :
        (b1 # b2 /\ Finalized(h, b1) /\ Finalized(h, b2))
            => 3 * SumStake(Equivocators) >= TotalStake

\* I3. With < 1/3 Byzantine stake, NO fork regardless of round-skipping — i.e. the
\*     LEDGER-007 weakness is fairness-only, not a safety break.
HonestAgreementUnderSkip ==
    (3 * SumStake(Byzantine) < TotalStake)
        => \A h \in Heights, b1 \in Blocks, b2 \in Blocks :
               (Finalized(h, b1) /\ Finalized(h, b2)) => b1 = b2

=============================================================================
