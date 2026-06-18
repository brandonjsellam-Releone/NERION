-------------------------- MODULE PolarSeekKernel --------------------------
(***************************************************************************)
(* Formal model of the PolarSeek admission kernel's SAFETY properties.     *)
(*                                                                         *)
(* Scope: the kernel decision function and the capability attenuation      *)
(* lattice ONLY (per the build spec, the formal scope is the kernel, not   *)
(* the whole system). This module is the machine-checkable statement of    *)
(* the properties the TypeScript property tests exercise:                  *)
(*                                                                         *)
(*   1. AttenuationMonotone  - delegation never amplifies authority.       *)
(*   2. DefaultDeny          - no authorizing capability => deny.          *)
(*   3. AllowImpliesAuth     - an `allow` implies a capability authorized. *)
(*   4. Determinism          - Decide is a function of its inputs.         *)
(*                                                                         *)
(* STATUS: authored, NOT yet machine-checked here (no TLA+/TLC/TLAPS       *)
(* toolchain in the P0/P1 build env). See kernel/spec/README.md. The TS    *)
(* property tests in kernel/test and capabilities/test are the executable  *)
(* counterpart and are green.                                              *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Actions,        \* set of action-type symbols
          Counterparties, \* set of counterparty symbols
          MaxInt,         \* upper bound for modeled integer amounts
          NullCeil        \* sentinel for "unrestricted" ceilings (e.g. -1)

Tiers == 0..3

(* A grant restricts authority along independent dimensions.               *)
Grant == [ actions     : SUBSET Actions,
           ceiling      : (0..MaxInt) \cup {NullCeil},
           aggCap       : (0..MaxInt) \cup {NullCeil},
           cps          : (SUBSET Counterparties) \cup {NullCeil},
           maxTier      : Tiers,
           notBefore    : 0..MaxInt,
           notAfter     : 0..MaxInt,
           delegable    : BOOLEAN ]

Intent == [ type : Actions,
            cp   : Counterparties \cup {NullCeil},
            amt  : 0..MaxInt ]

Ctx == [ now : 0..MaxInt, tier : Tiers, agg : 0..MaxInt ]

CeilOk(amt, c)  == (c = NullCeil) \/ (amt <= c)
AggOk(agg, amt, c) == (c = NullCeil) \/ (agg + amt <= c)
CpOk(cp, set)   == (set = NullCeil) \/ (cp \in set)

(* The pure authorization predicate (mirrors authorizesIntent in TS).      *)
Authorizes(g, i, x) ==
    /\ i.type \in g.actions
    /\ x.now >= g.notBefore /\ x.now <= g.notAfter
    /\ x.tier <= g.maxTier
    /\ CpOk(i.cp, g.cps)
    /\ CeilOk(i.amt, g.ceiling)
    /\ AggOk(x.agg, i.amt, g.aggCap)

CeilNarrows(c, p) == (p = NullCeil) \/ (c # NullCeil /\ c <= p)
SetNarrows(c, p)  == (p = NullCeil) \/ (c # NullCeil /\ c \subseteq p)

(* child is a valid attenuation of parent (mirrors isAttenuationOf in TS).  *)
IsAttenuation(c, p) ==
    /\ c.actions \subseteq p.actions
    /\ CeilNarrows(c.ceiling, p.ceiling)
    /\ CeilNarrows(c.aggCap, p.aggCap)
    /\ SetNarrows(c.cps, p.cps)
    /\ c.maxTier <= p.maxTier
    /\ c.notBefore >= p.notBefore
    /\ c.notAfter <= p.notAfter
    /\ (c.delegable => p.delegable)

(*-------------------------- SAFETY THEOREMS ----------------------------*)

(* 1. Attenuation never amplifies authority: anything a child authorizes,  *)
(*    its parent also authorizes.                                          *)
THEOREM AttenuationMonotone ==
    \A c, p \in Grant, i \in Intent, x \in Ctx :
        (IsAttenuation(c, p) /\ Authorizes(c, i, x)) => Authorizes(p, i, x)

(* 2. Decide over a set of candidate grants. Default-deny: empty set or no  *)
(*    authorizing grant yields deny.                                        *)
Decide(grants, i, x) ==
    IF \E g \in grants : Authorizes(g, i, x) THEN "allow" ELSE "deny"

THEOREM DefaultDeny ==
    \A i \in Intent, x \in Ctx : Decide({}, i, x) = "deny"

(* 3. An allow implies some capability authorized the intent.              *)
THEOREM AllowImpliesAuth ==
    \A grants \in SUBSET Grant, i \in Intent, x \in Ctx :
        (Decide(grants, i, x) = "allow") => (\E g \in grants : Authorizes(g, i, x))

(* 4. Determinism is immediate: Decide, Authorizes, IsAttenuation are       *)
(*    operators (pure functions) of their arguments, so equal inputs give   *)
(*    equal outputs by definition.                                          *)
=============================================================================
