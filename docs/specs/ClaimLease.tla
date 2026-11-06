---------------------------- MODULE ClaimLease ----------------------------
(* Decision 0032 points 30 to 38, version 2 (after the second adversarial review, docs/reviews/2026-11-05-0032-adversarial review-2.md).
   One lease resting on one claim. The desk signs bundles that travel to the edge and can be held back and delivered
   late (M1). The adversary holds the edge's wall clock, reboots the edge and cuts it off; the edge accepts a bundle
   within the protocol's skew of its trusted time (M4). The issuer revokes, and the desk may receive its status lists
   late (M9). The officer's revocation lives in the signer's log, so a desk restore keeps it (M2). The boot clock may
   freeze (a paused virtual machine) while the wall clock is honest, and the wall clock may be set while the boot clock
   runs; at every wake the edge records a new anchor, the later raw reading (edge protocol 1.5 section 1). One clock at
   a time, and no rollback of the edge's state, are the deployment's assumptions: the variants BothClocks and
   EdgeReverted show what breaks without them (M3), NoRatchet and RatchetTrusted what breaks without the ratchet or with
   one that records the skew-tolerant reading. tools/model_claim_lease.py is the same model in
   Python; at the same bounds both reach the same number of distinct states.

   With S the skew, an end is acted on at most 2 S late (edge protocol 1.5, section 1):
   - BoundedExposure: never usable at or after the lease's end + 2 S, the claim's end + 2 S, or, once the issuer
     revoked, the revocation + the offline reliance + 2 S.
   - OfficerBounded: once the officer revoked, never usable at or after the revocation + the horizon + 2 S.
   - NoResurrect: once the edge applied a bundle issued after the officer's revocation, never usable again. *)
EXTENDS Integers, FiniteSets

CONSTANTS MaxT, LEnd, Valid, H, Reliance, Skew, MaxSerial, Variant

VARIABLES now, wall, boot, bootValid, anchor, bootAtVerify, signedT, edgeSerial, edgeEnd, floorEnd, connected,
          issuerRevoked, revokedAt, statusAt, sees, officerRevoked, officerEver, officerAt, officerDelivered,
          nextSerial, inflight, paused

vars == <<now, wall, boot, bootValid, anchor, bootAtVerify, signedT, edgeSerial, edgeEnd, floorEnd, connected,
          issuerRevoked, revokedAt, statusAt, sees, officerRevoked, officerEver, officerAt, officerDelivered,
          nextSerial, inflight, paused>>

Inf == MaxT + 100
Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b

Init == /\ now = 0 /\ wall = 0 /\ boot = 0 /\ bootValid = FALSE /\ anchor = 0 /\ bootAtVerify = 0 /\ signedT = 0
        /\ edgeSerial = 0 /\ edgeEnd = 0 /\ floorEnd = Inf /\ connected = TRUE
        /\ issuerRevoked = FALSE /\ revokedAt = 0 /\ statusAt = 0 /\ sees = FALSE
        /\ officerRevoked = FALSE /\ officerEver = FALSE /\ officerAt = 0 /\ officerDelivered = FALSE
        /\ nextSerial = 1 /\ inflight = {} /\ paused = FALSE

Trusted == IF Variant = "BrokenTime" THEN Max(wall, signedT)
           ELSE IF ~bootValid THEN wall
           ELSE LET byBoot == anchor + boot - bootAtVerify IN IF byBoot > wall + Skew THEN byBoot ELSE wall

CanUse == edgeEnd > Trusted /\ (bootValid \/ Variant = "NoRebootLock")

Fold == IF officerRevoked \/ sees THEN now
        ELSE LET bound == Min(Min(LEnd, Valid), now + H)
             IN IF Variant = "NoReliance" THEN bound ELSE Min(bound, statusAt + Reliance)

edge == <<bootValid, anchor, bootAtVerify, signedT, edgeSerial, edgeEnd, floorEnd, paused>>
OneAtATime == Variant # "BothClocks"        \* the deployment's assumption: never both clocks tampered at once
desk == <<issuerRevoked, revokedAt, statusAt, sees, officerRevoked, officerEver, officerAt, officerDelivered,
          nextSerial, inflight>>

(* A wake: real time, the wall clock, and the boot clock unless frozen; with a bundle verified in this boot the edge
   records a new anchor, the later of the boot reading and the wall clock (never the skew-tolerant trusted time). *)
Tick == /\ now < MaxT
        /\ now' = now + 1 /\ wall' = Min(wall + 1, MaxT)
        /\ boot' = IF paused THEN boot ELSE boot + 1
        /\ LET byBoot == anchor + boot' - bootAtVerify
                tol == IF byBoot > wall' + Skew THEN byBoot ELSE wall'
                ratchet == bootValid /\ Variant # "NoRatchet"
           IN /\ anchor' = IF ~ratchet THEN anchor ELSE IF Variant = "RatchetTrusted" THEN tol ELSE Max(byBoot, wall')
              /\ bootAtVerify' = IF ratchet THEN boot' ELSE bootAtVerify
        /\ UNCHANGED <<connected, bootValid, signedT, edgeSerial, edgeEnd, floorEnd, paused, desk>>

(* The boot clock freezes (a paused VM) only while the wall clock is honest, and thaws. *)
Freeze == /\ ~paused /\ (~OneAtATime \/ wall = now)
          /\ paused' = TRUE
          /\ UNCHANGED <<now, wall, boot, connected, bootValid, anchor, bootAtVerify, signedT, edgeSerial, edgeEnd,
                         floorEnd, desk>>
Thaw == /\ paused /\ paused' = FALSE
        /\ UNCHANGED <<now, wall, boot, connected, bootValid, anchor, bootAtVerify, signedT, edgeSerial, edgeEnd,
                       floorEnd, desk>>

SetWall == /\ ~(OneAtATime /\ paused)
           /\ \E w \in 0..MaxT : w # wall /\ wall' = w
           /\ UNCHANGED <<now, boot, connected, edge, desk>>

Reboot == /\ boot' = 0 /\ bootValid' = FALSE
          /\ UNCHANGED <<now, wall, connected, anchor, bootAtVerify, signedT, edgeSerial, edgeEnd, floorEnd, paused,
                         desk>>

Cut == /\ connected' = ~connected
       /\ UNCHANGED <<now, wall, boot, edge, desk>>

IssuerRevoke == /\ ~issuerRevoked
                /\ issuerRevoked' = TRUE /\ revokedAt' = now
                /\ UNCHANGED <<now, wall, boot, connected, edge, statusAt, sees, officerRevoked, officerEver,
                               officerAt, officerDelivered, nextSerial, inflight>>

(* A status list issued at t reaches the desk; an older one than the desk holds changes nothing. *)
Fetch == /\ \E t \in statusAt..now :
              /\ sees' = (sees \/ (issuerRevoked /\ revokedAt <= t))
              /\ statusAt' = IF Variant = "FetchStamped" THEN now ELSE t
         /\ UNCHANGED <<now, wall, boot, connected, edge, issuerRevoked, revokedAt, officerRevoked, officerEver,
                        officerAt, officerDelivered, nextSerial, inflight>>

OfficerRevoke == /\ ~officerRevoked
                 /\ officerRevoked' = TRUE /\ officerEver' = TRUE
                 /\ officerAt' = IF officerEver THEN officerAt ELSE now
                 /\ UNCHANGED <<now, wall, boot, connected, edge, issuerRevoked, revokedAt, statusAt, sees,
                                officerDelivered, nextSerial, inflight>>

(* An older backup: an older status list, with what it said; the officer's revocation is in the signer's log. *)
Restore == /\ \E old \in 0..statusAt :
                /\ statusAt' = old
                /\ sees' = (issuerRevoked /\ revokedAt <= old)
           /\ officerRevoked' = (officerRevoked /\ Variant # "RestoreForgets")
           /\ UNCHANGED <<now, wall, boot, connected, edge, issuerRevoked, revokedAt, officerEver, officerAt,
                          officerDelivered, nextSerial, inflight>>

Issue == /\ nextSerial <= MaxSerial
         /\ inflight' = inflight \cup {[serial |-> nextSerial, issued |-> now, fold |-> Fold,
                                        revokes |-> (officerRevoked \/ sees), officer |-> officerRevoked]}
         /\ nextSerial' = nextSerial + 1
         /\ UNCHANGED <<now, wall, boot, connected, edge, issuerRevoked, revokedAt, statusAt, sees, officerRevoked,
                        officerEver, officerAt, officerDelivered>>

(* The edge rolled back to an earlier snapshot: its floors and its boot clock with it. *)
Revert == /\ Variant = "EdgeReverted" /\ bootValid
          /\ edgeSerial' = 0 /\ signedT' = 0 /\ floorEnd' = Inf /\ boot' = bootAtVerify
          /\ UNCHANGED <<now, wall, connected, bootValid, anchor, bootAtVerify, edgeEnd, paused, desk>>

(* A bundle reaches the edge: above its serial floor, not older than its newest signed time, not more than the skew
   ahead of its trusted time; after a reboot only a fresh one (answering a nonce of this boot, issued now). The edge
   records its trusted time, never its raw wall clock; a bundle is complete, so a revoked lease is absent. *)
Deliver == /\ connected
           /\ \E b \in inflight :
                /\ b.serial > edgeSerial /\ b.issued >= signedT /\ b.issued <= Trusted + Skew
                /\ (bootValid \/ Variant = "NoFreshAfterReboot" \/ b.issued = now)
                /\ anchor' = IF Variant = "AnchorRawWall" THEN wall
                             ELSE IF bootValid THEN Trusted
                             ELSE IF Variant = "NoFreshAfterReboot" THEN wall
                             ELSE Max(wall, b.issued)
                /\ floorEnd' = IF b.revokes THEN 0 ELSE floorEnd
                /\ edgeEnd' = Min(b.fold, IF b.revokes THEN 0 ELSE floorEnd)
                /\ officerDelivered' = (officerDelivered \/ b.officer)
                /\ edgeSerial' = b.serial /\ signedT' = b.issued
           /\ bootAtVerify' = boot /\ bootValid' = TRUE
           /\ UNCHANGED <<now, wall, boot, connected, paused, issuerRevoked, revokedAt, statusAt, sees, officerRevoked,
                          officerEver, officerAt, nextSerial, inflight>>

Next == Tick \/ Freeze \/ Thaw \/ SetWall \/ Reboot \/ Cut \/ IssuerRevoke \/ Fetch \/ OfficerRevoke \/ Restore \/ Issue
        \/ Revert \/ Deliver

Spec == Init /\ [][Next]_vars

BoundedExposure == CanUse => /\ now < LEnd + 2 * Skew
                             /\ now < Valid + 2 * Skew
                             /\ (issuerRevoked => now < revokedAt + Reliance + 2 * Skew)
OfficerBounded == CanUse => (officerEver => now < officerAt + H + 2 * Skew)
NoResurrect == CanUse => ~officerDelivered
=============================================================================
