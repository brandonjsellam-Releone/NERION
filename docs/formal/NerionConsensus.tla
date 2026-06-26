\* SPDX-FileCopyrightText: 2026 TRELYAN
\* SPDX-License-Identifier: Apache-2.0
------------------------------ MODULE NerionConsensus ------------------------------
(***************************************************************************)
(* A TLA+ MODEL of the Nerion stake-finality consensus core, faithful to   *)
(* ledger/src/equivocation.ts and governance/src/quorum.ts.                 *)
(*                                                                          *)
(* It models the *accountable safety* property the implementation relies    *)
(* on (Casper-style): a block is finalized when STRICTLY MORE than 2/3 of    *)
(* total stake attests it; if two DISTINCT blocks are ever finalized at the  *)
(* same height, then >= 1/3 of total stake must have equivocated (double-    *)
(* signed at one height) and is therefore slashable.                        *)
(*                                                                          *)
(* IMPORTANT (no overclaim): this is a MODEL of an ABSTRACTION. Model        *)
(* checking it with TLC finds counterexamples to the invariants over a small *)
(* finite configuration; it does NOT prove the TypeScript/Rust              *)
(* implementation correct, and it abstracts away signatures, networking,    *)
(* timing, and view-change. See README.md.                                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Validators,   \* set of validator identities
    Stake,        \* [Validators -> Nat] : stake weight per validator
    Byzantine,    \* SUBSET Validators : validators permitted to equivocate
    Heights,      \* set of block heights (small, e.g. {h1})
    Blocks        \* set of candidate block ids at a height (e.g. {ba, bb})

ASSUME ByzantineIsSubset == Byzantine \subseteq Validators
ASSUME StakeIsNat        == Stake \in [Validators -> Nat]

VARIABLE attested   \* [Validators -> SUBSET (Heights \X Blocks)]
vars == << attested >>

\* A convenient all-equal stake assignment for the default model (overridden
\* from the .cfg via  Stake <- EqualStake). Replace with a non-uniform function
\* to exercise stake-weighting.
EqualStake == [v \in Validators |-> 1]

RECURSIVE SumStake(_)
SumStake(S) == IF S = {} THEN 0
                ELSE LET v == CHOOSE x \in S : TRUE
                     IN  Stake[v] + SumStake(S \ {v})

TotalStake == SumStake(Validators)

Attestors(h, b) == { v \in Validators : << h, b >> \in attested[v] }

\* Stake-finality: STRICTLY more than 2/3 of total stake attested (h, b).
\* Mirrors the ">= 2/3" / accountable-finality threshold in equivocation.ts,
\* written as the strict integer form  3*S > 2*Total.
Finalized(h, b) == 3 * SumStake(Attestors(h, b)) > 2 * TotalStake

\* A validator equivocates iff it attested two DISTINCT blocks at the SAME height
\* (exactly detectEquivocations / verifyEquivocationProof's same-height rule).
Equivocates(v) ==
    \E h \in Heights, b1 \in Blocks, b2 \in Blocks :
        /\ b1 # b2
        /\ << h, b1 >> \in attested[v]
        /\ << h, b2 >> \in attested[v]

Equivocators == { v \in Validators : Equivocates(v) }

TypeOK == attested \in [Validators -> SUBSET (Heights \X Blocks)]

Init == attested = [v \in Validators |-> {}]

\* An honest validator attests at most ONE block per height.
HonestFreeAt(v, h) == \A bb \in Blocks : << h, bb >> \notin attested[v]

\* One step: validator v attests block b at height h. Byzantine validators may
\* equivocate; honest validators may not.
Attest(v, h, b) ==
    /\ << h, b >> \notin attested[v]
    /\ (v \in Byzantine \/ HonestFreeAt(v, h))
    /\ attested' = [attested EXCEPT ![v] = @ \cup { << h, b >> }]

Next == \E v \in Validators, h \in Heights, b \in Blocks : Attest(v, h, b)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants — checked by TLC in every reachable state.                   *)
(***************************************************************************)

\* I1. Honest validators never equivocate, hence are never slashable.
\*     (Models the LEDGER-EQUIV-001 guarantee in verifyEquivocationProof:
\*      only genuine same-height double-signers are slashable.)
NoHonestEquivocation == \A v \in (Validators \ Byzantine) : ~ Equivocates(v)

\* I2. ACCOUNTABLE SAFETY (the headline property). If two distinct blocks are
\*     both finalized at the same height, then >= 1/3 of total stake equivocated.
AccountableSafety ==
    \A h \in Heights, b1 \in Blocks, b2 \in Blocks :
        (b1 # b2 /\ Finalized(h, b1) /\ Finalized(h, b2))
            => 3 * SumStake(Equivocators) >= TotalStake

\* I3. HONEST AGREEMENT. With strictly less than 1/3 Byzantine stake, no two
\*     distinct blocks are finalized at the same height (since honest validators
\*     never equivocate, equivocators \subseteq Byzantine < 1/3, contradicting I2).
HonestAgreement ==
    (3 * SumStake(Byzantine) < TotalStake)
        => \A h \in Heights, b1 \in Blocks, b2 \in Blocks :
               (Finalized(h, b1) /\ Finalized(h, b2)) => b1 = b2

\* I4. QUORUM INTEGRITY. A finalized block always carries a > 2/3 stake quorum —
\*     a guard that the finalization predicate is never silently weakened.
QuorumIntegrity ==
    \A h \in Heights, b \in Blocks :
        Finalized(h, b) => 3 * SumStake(Attestors(h, b)) > 2 * TotalStake

=============================================================================
