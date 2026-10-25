# Test plan: many people at once, and the state machines behind them

Status: plan (operator, 2026-10-23: "start testing a prd version, a server running and then multiple people connecting
at the same time, triggering requests and approvals and changes all at the same time, and follow up on those state
machines").

## Target
The local stack on the pinned engine image (as production runs it), Keycloak as the broker, approvals with proofs.

## Harness
- N simulated people (staff, deputies, the officer, a viewer, the front office), each signing in through the broker the
  way a browser does; approvals use the real approval sign-in (statement, nonce, fresh sign-in, proof).
- Each person runs a loop of legal actions chosen at random (propose, preview, approve, withdraw, read views; visits,
  entries, badges, codes), with deliberate collisions: two approvers on one change, a withdraw racing an approval, the
  same change proposed twice, a timer firing during a confirmation, the write limit reached, a reconcile mid-change.
- Every request and answer is recorded (status, time, change id).

## Invariants checked after a run
1. The signed change log is intact and its revisions count up by one with no gaps (the Broker page's log check).
2. Every change ends in exactly one legal state: applied, refused, withdrawn or expired; pending only while waiting;
   never applied twice; an approval never counted twice.
3. No answer is a 5xx; every refusal carries a reason.
4. No id is used twice, none is lost; every applied change's records are in the final records.
5. The final records pass every engine check; the broker converges to the records within one reconcile.
6. Visit and badge state machines: no entry after a suspension, no badge after leaving, timers fire once.

## In the engine
A Hypothesis state-machine test of the desk (no network): the same actions and invariants, shrunk to a minimal
failing sequence when one breaks.

## The desk on the change log: its fault model
Decision 0022 S5, accepted 2026-10-25. A change on the change log moves through proposed (the desk built it), linked
(the signer judged it, signed it and kept it), followed (the desk's replica holds the link) and noted (the desk's
activity log names the link). The desk never signs and never buffers a write. Each fault below is injected by a test:

| Fault | What the desk does | Test |
|---|---|---|
| Two writers, or a link the desk has not followed: a stale base | the signer refuses it whole; the desk follows and says to look again; nothing overwrites the other change | `test_log_faults.py::test_a_stale_write_is_refused_whole_and_never_overwrites_another` |
| The answer lost, the change proposed again | the signer answers with the link it already is; never applied twice | `test_log_desk.py::test_a_change_whose_answer_was_lost_is_not_applied_twice` |
| The signer unreachable | reads go on from the replica; writes refused with the reason; nothing queued | `test_log_faults.py::test_with_the_signer_down_reads_go_on_and_writes_are_refused_unbuffered` |
| The desk stops between the link and its line | at its next start, one line per unnoted link, marked recovered | `test_log_faults.py::test_a_desk_that_stopped_between_the_link_and_its_line_writes_it_at_start` |
| A link the replica refuses, or a refresh that fails | not ready with the reason, counted in `keyclerk_log_breaks`, resynced from the signer, healed on the next refresh | `test_log_faults.py::test_a_desk_that_cannot_follow_is_not_ready_says_why_and_heals`, `test_signer_replica.py::test_a_desk_that_lost_its_store_or_fell_behind_resyncs` |
| The replica deleted | rebuilt from the signer at start, to the same head and records | `test_log_desk.py::test_a_desk_whose_replica_was_deleted_rebuilds_it_from_the_signer` |
| Signing frozen | ready and read-only, saying why; `keyclerk_signing_frozen` 1; writes refused with the freeze's reason | `test_log_faults.py::test_a_frozen_signer_leaves_the_desk_ready_and_read_only_and_says_so` |
| The replica restored from a newer backup than its signer | refused at start with what to do; rebuilt once removed | `test_log_faults.py::test_a_replica_restored_newer_than_its_signer_is_refused` |
| A refused visit timer step (a suspension that did not happen) | `keyclerk_timer_refused_total`, a log line, the activity line | `test_log_faults.py::test_a_refused_timer_step_is_an_alarm` |

The signer's own faults (a crash inside a proposal is one transaction; a replica restored older than what it signed
refuses to sign; a tampered audit log refuses) are in `test_signer_replica.py`. The many-people soak tool runs on
the change log as an 0.26.x item.
