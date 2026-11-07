---------------------------- MODULE SignerFailover ----------------------------
(* Decision 0031: in HA mode a change to the signed change log commits when the realm's commit witness takes its   *)
(* checkpoint by compare-and-swap (c2sp.org/tlog-witness: the old size must be the witness's newest and the new     *)
(* tree consistent with it, checked and persisted as one step). The commit witness also keeps the committed links'  *)
(* bodies, so a standby can always fetch them. Consumers (desks, followers, edges) act only on the committed head,   *)
(* and a proposer is answered only once its link is committed.                                                     *)
(*                                                                                                                  *)
(* Any signer may ask anything at any time, pause for any length, crash, or be restored to an older state; the     *)
(* network delays, drops, duplicates and replays submissions. No clock appears: timers only decide when a standby   *)
(* tries, which is liveness. Two people may switch the realm to break-glass: one named signer signs unwitnessed     *)
(* from a base (the newest head the desk saw), with the commit witness stopped; that signer follows no witness, and *)
(* a restore of it resumes at the newest head consumers acted on (decision 0019). The witness's owner may re-seed a *)
(* lost witness from the newest head the desk saw, never from nothing.                                             *)
(*                                                                                                                  *)
(* Decision 0033: each node's records key is held by its key custodian, the authority on positions. log[s] is what  *)
(* node s's custodian holds. It signs only the next position, never while it holds fewer links than its persisted   *)
(* witness floor; at start it reads the witness and raises its floor to the witness's size, so behind it, it signs *)
(* nothing until it has followed (point 5), and it stops only on a witness below its floor or another tree at its   *)
(* own size. It follows the committed log only onto the witness's tree and never below its own size (review      *)
(* 2026-11-07, D2): a deposed node whose uncommitted tail the active node has not passed waits. Two people may      *)
(* bring the committed log to a stuck custodian (the recovery ceremony, Q6), the one way below its own size: one    *)
(* stopped at start, or holding a fork past the committed log. Ghosts: hw[s], the most links                       *)
(* s's custodian held since its last restore or ceremony; known[s], the largest committed size it was ever shown.  *)
(* What stays open: a restore from an older copy that is not behind the witness forgets the uncommitted positions it *)
(* signed, so it may sign one of them again (the TPM counter narrows this to a checkpoint epoch, Q8).              *)
(*                                                                                                                  *)
(* Eight flags each break one assumption; each must yield a counterexample (docs/specs/SignerFailover-*.cfg):      *)
(*   ActOnUncommitted    consumers act on a signer's own log                                                        *)
(*   WitnessRollback     the commit witness is restored from an older backup                                       *)
(*   SplitCAS            the witness checks and writes a submission in two steps                                    *)
(*   NoBodies            the commit witness keeps checkpoints only, not the links' bodies                            *)
(*   UnfencedBreakGlass  the commit witness keeps taking appends after the break-glass switch                        *)
(*   ResetEmpty          the witness is reset to an empty log instead of seeded                                     *)
(*   NoStartCheck        a custodian starts without raising its floor to the witness's (a restored one signs again)  *)
(*   FollowBelowOwn      a custodian follows a committed log shorter than what it holds                              *)
(* tools/model_signer_failover.py explores the same transition system exhaustively.                               *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Signers, MaxSigns, MaxLen, MaxMsgs,
          ActOnUncommitted, WitnessRollback, SplitCAS, NoBodies, UnfencedBreakGlass, ResetEmpty,
          NoStartCheck, FollowBelowOwn

VARIABLES log, ctr, alive, wit, backup, msgs, checked, acted, answered, mode, bg, floor, stopped, hw, known

cust == <<floor, stopped, hw, known>>
vars == <<log, ctr, alive, wit, backup, msgs, checked, acted, answered, mode, bg, floor, stopped, hw, known>>

Max(a, b) == IF a > b THEN a ELSE b
Min(a, b) == IF a < b THEN a ELSE b
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
    /\ floor = [s \in Signers |-> 0] /\ stopped = [s \in Signers |-> FALSE]
    /\ hw = [s \in Signers |-> 0] /\ known = [s \in Signers |-> 0]

\* The custodian of s starts holding l with floor f: it reads the witness and raises its floor to the witness's size
\* (behind it, it signs nothing until it has followed); it stops only on a witness below its floor (rolled back) or
\* another tree at its own size, which the ceremony settles (point 5).
Started(s, l, f) ==
    LET bad == Len(wit) < f \/ (Len(wit) = Len(l) /\ wit # l) IN
      /\ stopped' = [stopped EXCEPT ![s] = ~NoStartCheck /\ bad]
      /\ floor' = [floor EXCEPT ![s] = IF NoStartCheck \/ bad THEN f ELSE Max(f, Len(wit))]
      /\ known' = [known EXCEPT ![s] = IF NoStartCheck THEN @ ELSE Max(@, Len(wit))]

Sign(s) ==              \* the custodian signs the next position only, and never while behind its floor
    /\ s \in alive /\ ~stopped[s] /\ ctr[s] < MaxSigns /\ Len(log[s]) < MaxLen /\ Len(log[s]) >= floor[s]
    /\ ctr' = [ctr EXCEPT ![s] = @ + 1] /\ log' = [log EXCEPT ![s] = Append(@, <<s, ctr[s] + 1>>)]
    /\ hw' = [hw EXCEPT ![s] = Max(@, Len(log[s]) + 1)]
    /\ UNCHANGED <<alive, wit, backup, msgs, checked, acted, answered, mode, bg, floor, stopped, known>>

Submit(s) ==            \* with any old size: a stale belief, a paused process, a lost answer
    /\ s \in alive /\ Len(log[s]) > 0 /\ Cardinality(msgs) < MaxMsgs
    /\ \E o \in 0..Len(log[s]) : msgs' = msgs \cup {[old |-> o, new |-> log[s]]}
    /\ UNCHANGED <<log, ctr, alive, wit, backup, checked, acted, answered, mode, bg>> /\ UNCHANGED cust

Accepts(m) == Len(wit) = m.old /\ IsPrefix(wit, m.new)

Witness(m) ==           \* the compare-and-swap, one step; the proposer is answered; the message may come again
    /\ ~SplitCAS /\ WitnessOn /\ m \in msgs /\ Accepts(m)
    /\ wit' = m.new /\ answered' = answered \cup {m.new}
    /\ UNCHANGED <<log, ctr, alive, backup, msgs, checked, acted, mode, bg>> /\ UNCHANGED cust
Check(m) ==
    /\ SplitCAS /\ WitnessOn /\ m \in msgs /\ Accepts(m) /\ checked' = checked \cup {m}
    /\ UNCHANGED <<log, ctr, alive, wit, backup, msgs, acted, answered, mode, bg>> /\ UNCHANGED cust
Write(m) ==
    /\ SplitCAS /\ m \in checked
    /\ wit' = m.new /\ checked' = checked \ {m} /\ answered' = answered \cup {m.new}
    /\ UNCHANGED <<log, ctr, alive, backup, msgs, acted, mode, bg>> /\ UNCHANGED cust
Drop(m) ==
    /\ m \in msgs /\ msgs' = msgs \ {m}
    /\ UNCHANGED <<log, ctr, alive, wit, backup, checked, acted, answered, mode, bg>> /\ UNCHANGED cust

Follow(s) ==            \* onto the witness's tree only, never below its floor nor below its own size (D2)
    /\ s \in alive /\ ~stopped[s] /\ log[s] # wit /\ CanFetch /\ ~GlassSigner(s)
    /\ Len(wit) >= floor[s] /\ (FollowBelowOwn \/ Len(wit) >= Len(log[s]))
    /\ log' = [log EXCEPT ![s] = wit] /\ floor' = [floor EXCEPT ![s] = Len(wit)]
    /\ hw' = [hw EXCEPT ![s] = Max(@, Len(wit))] /\ known' = [known EXCEPT ![s] = Max(@, Len(wit))]
    /\ UNCHANGED <<ctr, alive, wit, backup, msgs, checked, acted, answered, mode, bg, stopped>>

Crash(s) == s \in alive /\ alive' = alive \ {s}
            /\ UNCHANGED <<log, ctr, wit, backup, msgs, checked, acted, answered, mode, bg>> /\ UNCHANGED cust
Recover(s) == s \notin alive /\ alive' = alive \cup {s} /\ Started(s, log[s], floor[s])
              /\ UNCHANGED <<log, ctr, wit, backup, msgs, checked, acted, answered, mode, bg, hw>>

RestoreSigner(s) ==     \* from an older copy (its floor no higher); the break-glass signer resumes at the newest
    /\ \E k \in (IF GlassSigner(s) THEN Len(Newest(acted)) ELSE 0)..(Len(log[s]) - 1) :   \* head acted on (0019)
           /\ log' = [log EXCEPT ![s] = SubSeq(@, 1, k)] /\ hw' = [hw EXCEPT ![s] = k]
           /\ IF s \in alive THEN Started(s, SubSeq(log[s], 1, k), Min(floor[s], k))
              ELSE floor' = [floor EXCEPT ![s] = Min(@, k)] /\ UNCHANGED <<stopped, known>>
    /\ UNCHANGED <<ctr, alive, wit, backup, msgs, checked, acted, answered, mode, bg>>

\* Stuck: refused to start while behind the witness, or a deposed node holding a fork past the committed log (D2).
Stuck(s) == stopped[s] \/ (Len(log[s]) > Len(wit) /\ ~IsPrefix(wit, log[s]))

Ceremony(s) ==          \* two people bring the committed log to a stuck custodian (recover, Q6): never below the witness
    /\ mode = "witnessed" /\ s \in alive /\ CanFetch /\ Stuck(s)
    /\ log' = [log EXCEPT ![s] = wit] /\ floor' = [floor EXCEPT ![s] = Len(wit)]
    /\ stopped' = [stopped EXCEPT ![s] = FALSE] /\ hw' = [hw EXCEPT ![s] = Len(wit)]
    /\ known' = [known EXCEPT ![s] = Max(@, Len(wit))]
    /\ UNCHANGED <<ctr, alive, wit, backup, msgs, checked, acted, answered, mode, bg>>

BreakGlass(s) ==        \* two people: s signs unwitnessed from the newest head the desk saw
    /\ mode = "witnessed" /\ s \in alive /\ IsPrefix(Newest(acted \cup answered), log[s])
    /\ mode' = "glass" /\ bg' = [signer |-> s, base |-> Newest(acted \cup answered)]
    /\ UNCHANGED <<log, ctr, alive, wit, backup, msgs, checked, acted, answered>> /\ UNCHANGED cust

Act ==
    \/ /\ WitnessOn /\ wit \notin acted /\ acted' = acted \cup {wit}
       /\ UNCHANGED <<log, ctr, alive, wit, backup, msgs, checked, answered, mode, bg>> /\ UNCHANGED cust
    \/ /\ mode = "glass" /\ IsPrefix(bg.base, log[bg.signer]) /\ log[bg.signer] \notin acted
       /\ acted' = acted \cup {log[bg.signer]} /\ answered' = answered \cup {log[bg.signer]}
       /\ UNCHANGED <<log, ctr, alive, wit, backup, msgs, checked, mode, bg>> /\ UNCHANGED cust
    \/ /\ ActOnUncommitted /\ \E s \in Signers : log[s] \notin acted /\ acted' = acted \cup {log[s]}
       /\ UNCHANGED <<log, ctr, alive, wit, backup, msgs, checked, answered, mode, bg>> /\ UNCHANGED cust

TakeBackup == WitnessRollback /\ backup # wit /\ backup' = wit
              /\ UNCHANGED <<log, ctr, alive, wit, msgs, checked, acted, answered, mode, bg>> /\ UNCHANGED cust
RestoreWitness == WitnessRollback /\ backup # wit /\ wit' = backup
                  /\ UNCHANGED <<log, ctr, alive, backup, msgs, checked, acted, answered, mode, bg>> /\ UNCHANGED cust

Reset ==                \* the owner re-seeds a lost witness from the newest head the desk saw (two people confirm)
    /\ mode = "witnessed"
    /\ LET seed == IF ResetEmpty THEN <<>> ELSE Newest(acted \cup answered) IN
         /\ seed # wit /\ wit' = seed /\ msgs' = {} /\ checked' = {}
    /\ UNCHANGED <<log, ctr, alive, backup, acted, answered, mode, bg>> /\ UNCHANGED cust

Next ==
    \/ \E s \in Signers : Sign(s) \/ Submit(s) \/ Follow(s) \/ Crash(s) \/ Recover(s) \/ RestoreSigner(s)
                          \/ Ceremony(s) \/ BreakGlass(s)
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
\* Outside the ceremony and a restore, a custodian never signs a second body at a position (a sign at or below what it
\* held is one: every body is new), and never at a position it was ever shown committed, restored or not.
CustodianOneBody == [][\A s \in Signers : ctr'[s] > ctr[s] => Len(log'[s]) > hw[s]]_vars
NoSignBelowCommitted == [][\A s \in Signers : ctr'[s] > ctr[s] => Len(log'[s]) > known[s]]_vars
=============================================================================
