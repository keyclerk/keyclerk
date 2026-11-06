---------------------------- MODULE SignerFailover ----------------------------
(* Decision 0031: in HA mode a change to the signed change log commits when the realm's commit witness takes its   *)
(* checkpoint by compare-and-swap (c2sp.org/tlog-witness: the old size must be the witness's newest and the new     *)
(* tree consistent with it, checked and persisted as one step). The commit witness also keeps the committed links'  *)
(* bodies, so a standby can always fetch them. Consumers (desks, followers, edges) act only on the committed head,   *)
(* and a proposer is answered only once its link is committed.                                                     *)
(*                                                                                                                  *)
(* Any signer may sign anything at any time (they share the records key), pause for any length, crash, or be        *)
(* restored to an older state; the network delays, drops, duplicates and replays submissions. No clock appears:     *)
(* timers only decide when a standby tries, which is liveness. Two people may switch the realm to break-glass: one  *)
(* named signer signs unwitnessed from a base (the newest head the desk saw), with the commit witness stopped; that  *)
(* signer follows no witness, and a restore of it resumes at the newest head consumers acted on (decision 0019).    *)
(* The witness's owner may re-seed a lost witness from the newest head the desk saw, never from nothing.           *)
(*                                                                                                                  *)
(* Six flags each break one assumption; each must yield a counterexample (docs/specs/SignerFailover-*.cfg):        *)
(*   ActOnUncommitted    consumers act on a signer's own log                                                        *)
(*   WitnessRollback     the commit witness is restored from an older backup                                       *)
(*   SplitCAS            the witness checks and writes a submission in two steps                                    *)
(*   NoBodies            the commit witness keeps checkpoints only, not the links' bodies                            *)
(*   UnfencedBreakGlass  the commit witness keeps taking appends after the break-glass switch                        *)
(*   ResetEmpty          the witness is reset to an empty log instead of seeded                                     *)
(* tools/model_signer_failover.py explores the same transition system exhaustively.                               *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Signers, MaxSigns, MaxLen, MaxMsgs,
          ActOnUncommitted, WitnessRollback, SplitCAS, NoBodies, UnfencedBreakGlass, ResetEmpty

VARIABLES log, ctr, alive, wit, backup, msgs, checked, acted, answered, mode, bg

vars == <<log, ctr, alive, wit, backup, msgs, checked, acted, answered, mode, bg>>

IsPrefix(a, b) == Len(a) <= Len(b) /\ SubSeq(b, 1, Len(a)) = a
Newest(S) == IF S = {} THEN <<>> ELSE CHOOSE x \in S : \A y \in S : Len(y) <= Len(x)
WitnessOn == mode = "witnessed" \/ UnfencedBreakGlass
GlassSigner(s) == mode = "glass" /\ bg.signer = s
\* A signer can get the committed links: from the witness's bodies, or from someone alive or a consumer holding them.
CanFetch == ~NoBodies \/ (\E t \in alive : IsPrefix(wit, log[t])) \/ (\E x \in acted : IsPrefix(wit, x))

Init ==
    /\ log = [s \in Signers |-> <<>>] /\ ctr = [s \in Signers |-> 0] /\ alive = Signers
    /\ wit = <<>> /\ backup = <<>> /\ msgs = {} /\ checked = {} /\ acted = {} /\ answered = {}
    /\ mode = "witnessed" /\ bg = [signer |-> "none", base |-> <<>>]

Sign(s) ==
    /\ s \in alive /\ ctr[s] < MaxSigns /\ Len(log[s]) < MaxLen
    /\ ctr' = [ctr EXCEPT ![s] = @ + 1] /\ log' = [log EXCEPT ![s] = Append(@, <<s, ctr[s] + 1>>)]
    /\ UNCHANGED <<alive, wit, backup, msgs, checked, acted, answered, mode, bg>>

Submit(s) ==            \* with any old size: a stale belief, a paused process, a lost answer
    /\ s \in alive /\ Len(log[s]) > 0 /\ Cardinality(msgs) < MaxMsgs
    /\ \E o \in 0..Len(log[s]) : msgs' = msgs \cup {[old |-> o, new |-> log[s]]}
    /\ UNCHANGED <<log, ctr, alive, wit, backup, checked, acted, answered, mode, bg>>

Accepts(m) == Len(wit) = m.old /\ IsPrefix(wit, m.new)

Witness(m) ==           \* the compare-and-swap, one step; the proposer is answered; the message may come again
    /\ ~SplitCAS /\ WitnessOn /\ m \in msgs /\ Accepts(m)
    /\ wit' = m.new /\ answered' = answered \cup {m.new}
    /\ UNCHANGED <<log, ctr, alive, backup, msgs, checked, acted, mode, bg>>
Check(m) ==
    /\ SplitCAS /\ WitnessOn /\ m \in msgs /\ Accepts(m) /\ checked' = checked \cup {m}
    /\ UNCHANGED <<log, ctr, alive, wit, backup, msgs, acted, answered, mode, bg>>
Write(m) ==
    /\ SplitCAS /\ m \in checked
    /\ wit' = m.new /\ checked' = checked \ {m} /\ answered' = answered \cup {m.new}
    /\ UNCHANGED <<log, ctr, alive, backup, msgs, acted, mode, bg>>
Drop(m) ==
    /\ m \in msgs /\ msgs' = msgs \ {m}
    /\ UNCHANGED <<log, ctr, alive, wit, backup, checked, acted, answered, mode, bg>>

Follow(s) ==            \* a standby follows the committed head; a deposed active drops its uncommitted tail
    /\ s \in alive /\ log[s] # wit /\ CanFetch /\ ~GlassSigner(s)
    /\ log' = [log EXCEPT ![s] = wit]
    /\ UNCHANGED <<ctr, alive, wit, backup, msgs, checked, acted, answered, mode, bg>>

Crash(s) == s \in alive /\ alive' = alive \ {s}
            /\ UNCHANGED <<log, ctr, wit, backup, msgs, checked, acted, answered, mode, bg>>
Recover(s) == s \notin alive /\ alive' = alive \cup {s}
              /\ UNCHANGED <<log, ctr, wit, backup, msgs, checked, acted, answered, mode, bg>>

RestoreSigner(s) ==     \* from an older backup; the break-glass signer resumes at the newest head acted on (0019)
    /\ \E k \in (IF GlassSigner(s) THEN Len(Newest(acted)) ELSE 0)..(Len(log[s]) - 1) :
           log' = [log EXCEPT ![s] = SubSeq(@, 1, k)]
    /\ UNCHANGED <<ctr, alive, wit, backup, msgs, checked, acted, answered, mode, bg>>

BreakGlass(s) ==        \* two people: s signs unwitnessed from the newest head the desk saw
    /\ mode = "witnessed" /\ s \in alive /\ IsPrefix(Newest(acted \cup answered), log[s])
    /\ mode' = "glass" /\ bg' = [signer |-> s, base |-> Newest(acted \cup answered)]
    /\ UNCHANGED <<log, ctr, alive, wit, backup, msgs, checked, acted, answered>>

Act ==
    \/ /\ WitnessOn /\ wit \notin acted /\ acted' = acted \cup {wit}
       /\ UNCHANGED <<log, ctr, alive, wit, backup, msgs, checked, answered, mode, bg>>
    \/ /\ mode = "glass" /\ IsPrefix(bg.base, log[bg.signer]) /\ log[bg.signer] \notin acted
       /\ acted' = acted \cup {log[bg.signer]} /\ answered' = answered \cup {log[bg.signer]}
       /\ UNCHANGED <<log, ctr, alive, wit, backup, msgs, checked, mode, bg>>
    \/ /\ ActOnUncommitted /\ \E s \in Signers : log[s] \notin acted /\ acted' = acted \cup {log[s]}
       /\ UNCHANGED <<log, ctr, alive, wit, backup, msgs, checked, answered, mode, bg>>

TakeBackup == WitnessRollback /\ backup # wit /\ backup' = wit
              /\ UNCHANGED <<log, ctr, alive, wit, msgs, checked, acted, answered, mode, bg>>
RestoreWitness == WitnessRollback /\ backup # wit /\ wit' = backup
                  /\ UNCHANGED <<log, ctr, alive, backup, msgs, checked, acted, answered, mode, bg>>

Reset ==                \* the owner re-seeds a lost witness from the newest head the desk saw (two people confirm)
    /\ mode = "witnessed"
    /\ LET seed == IF ResetEmpty THEN <<>> ELSE Newest(acted \cup answered) IN
         /\ seed # wit /\ wit' = seed /\ msgs' = {} /\ checked' = {}
    /\ UNCHANGED <<log, ctr, alive, backup, acted, answered, mode, bg>>

Next ==
    \/ \E s \in Signers : Sign(s) \/ Submit(s) \/ Follow(s) \/ Crash(s) \/ Recover(s) \/ RestoreSigner(s) \/ BreakGlass(s)
    \/ \E m \in msgs : Witness(m) \/ Check(m) \/ Drop(m)
    \/ \E m \in checked : Write(m)
    \/ Act \/ TakeBackup \/ RestoreWitness \/ Reset

Spec == Init /\ [][Next]_vars

\* --- what must hold --------------------------------------------------------------------------------------------
OneHistory == \A x, y \in acted : IsPrefix(x, y) \/ IsPrefix(y, x)                 \* never two histories acted on
ActedCommitted == mode = "witnessed" => \A x \in acted \cup answered : IsPrefix(x, wit)   \* acted on or answered: committed
Takeover ==                                                                          \* a standby that is up can take over
    (mode = "witnessed" /\ Len(wit) < MaxLen /\ \E s \in alive : ctr[s] < MaxSigns) => CanFetch
CommitOnlyGrows == [][(mode = "witnessed" /\ mode' = "witnessed" /\ ~Reset) => IsPrefix(wit, wit')]_vars
=============================================================================
