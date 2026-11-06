# 0031. High availability: two-node edges, and a standby core signer whose commits the witness serialises

- Status: accepted (2026-11-04). The maintainer agreed to the design on condition that it be modelled and reviewed
  adversarially first; it was revised twice after adversarial reviews and once after a prior-art study, and TLC checked it at the full bound.
  Supersedes, for the core signer, "a witness grant" in decision 0030 point 6 and in roadmap step 7. Builds on 0014 (two nodes in an edge's statement), 0019 (restore and its mark), 0022 point 6 (built once, on
  the log), 0027 (the site key and its promotion statement) and the edge implementation's own decision on its election (three votes, the witness by profile).
- Context: an edge may run two nodes (the edge implementation's high-availability profile), and the core signer is one process. A lost core host stops new
  signed changes, a leaver's revocation among them, until a restore (40 s measured, decision 0029 point 9) and a
  two-person mark. Access never stops, because edges run on their horizons. 0030 point 6 asks for one promotion model,
  never on a timeout, so a network split cannot produce two histories. The maintainer added two rules (2026-11-04):
  no more machinery than needed, and nothing extra when a deployment does not use HA; and asked how an HSRP-like
  automatic, two-way takeover could be done properly.

## Prior art and the standards it rests on
References are in docs/references.md.
- **One writer by compare-and-swap, not election.** Sunlight [SUNLIGHT] keeps a single writer for a Certificate
  Transparency log through a store with compare-and-swap semantics holding the latest checkpoint: a writer publishes
  only by swapping its checkpoint in over the previous one.
- **The C2SP witness is that compare-and-swap.** It accepts a checkpoint only when the old size matches the newest it
  countersigned and the new tree is consistent with it (an RFC 9162 [RFC9162] consistency proof), and must check and
  persist as one step [C2SP]. KeyClerk's witness does so today (0.27.0).
- **Fencing, not clocks.** A paused process can always wake and act on a stale belief, so safety comes from the
  resource refusing stale writers; clocks may drive timeouts only [KLEPPMANN], as Chubby's sequencers did beside its
  leases [CHUBBY]. Leases are safe only under bounded clock drift [LEASES], which this design avoids depending on.
- **A third vote on a separate host.** A two-node cluster needs a tie-breaker that is not one of its nodes, on a separate
  host and network: corosync's qnetd [QNETD]. Here the commit witness is that third party.
- **Why not HSRP or VRRP as such.** HSRP [RFC2281] and VRRP [RFC5798] take over on a hold timer with no third vote. For
  an address, a moment with two active routers costs a few duplicate packets. For a signer it costs two histories signed
  with one key. The takeover stays automatic and two-way here, but the witness referees it.
- **Why not consensus.** Raft [RAFT] gives a replicated log with terms and a majority. A single writer refereed by a
  compare-and-swap needs neither, and runs no new component.
- **Bounded model checking.** Exhaustive checking at small bounds finds the design errors that matter (the small scope
  hypothesis [SMALLSCOPE]); the model is written in TLA+ [TLAPLUS].

## Decision (proposed)
1. **Per-node state on the desk (edges).** An edge's record may state a second node (`node2`: its own enrolment key,
   unlock key and TPM, in the officer's signed statement beside the first). Either node's key signs its requests, and
   the desk keeps each node's last pull, report and echoed head apart. Bundles and the serial floor stay per edge.
   Built 2026-11-04.
2. **A node says how it became active (edge protocol 1.5).** `activation {by, at, statement?}` in its report: `witness`
   (a majority with the core), `local_witness` (a majority with the site's own witness device) or `break_glass` (the
   site key's `promotion` statement, carried whole, which the desk verifies). KeyClerk records each change of the
   active node and raises an incident for a break-glass promotion; the edge implementation elects.
3. **HA is signed realm configuration.** A head record `ha {origin, commit_witness (its vkey), standbys}` in the change
   log turns HA on. Consumers read it from the log, never from its absence, so it cannot be downgraded by omission, and
   a new commit witness after a loss is named the same way. After the realm's seed the record is put or removed only by
   an HA change link the security officer and a root trust owner each confirmed, as a restore link (operator
   2026-11-05): HA on, off, other nodes, another commit witness, or a break-glass (point 10). The link format refuses
   any other link that touches it. Built 2026-11-05 (`python -m keyclerk.ha`).
4. **In HA mode a change commits when the commit witness takes it.** The active signer signs a link, submits the
   checkpoint covering it, with the link's body, to the commit witness, and answers the proposal only once the
   compare-and-swap succeeded. A lost answer leaves the outcome unknown, never refused: the desk asks again with the
   change's id, and the witness's equal-size answer confirms it.
5. **The commit witness keeps the committed links' bodies.** So a standby can fetch every committed link even when the
   active died right after the commit: no committed link exists only on a dead host.
6. **Consumers act only on committed heads.** Desks, followers and edge bundles adopt a size only with the commit
   witness's cosignature on it; links above it are held pending, never applied. A desk store gains the means to drop a
   pending tail.
   Built 2026-11-05 for desks and followers: the active node serves the commit witness's countersigned checkpoint in
   `head` and in each answer, and the follower checks the records key's signature and the commit witness's cosignature
   itself, adopting links only up to that size and refusing links that reach another root. Without the countersignature
   it adopts nothing (the desk reads on); from the link that switches HA on, even a resync from nothing is held to it.
   Edge bundles are built from the desk's replica, so they carry committed heads only. A desk needs no means to drop a
   tail: it never takes one.
7. **Takeover goes both ways by itself.**
   - A standby follows the committed head (from the witness, with the bodies).
   - When that head has not moved for the whole of its timer, the standby appends a new link. A standby never "takes
     over" by resubmitting a checkpoint of equal size, which fences nothing.
   - If the active is alive and moving, the head moves within the timer and the standby does not try, so a healthy
     active is not deposed. **Amended 2026-11-05:** an idle active moves nothing, so in the first soak on a quiet realm
     the standby took over at every hold time and the two nodes handed over for ever. The active now beats: at most
     every third of its hold time it commits its committed checkpoint again, with no links, and the commit witness
     countersigns it again at a later time of its own (its last time + 1 at least, so a beat always moves it). A
     standby counts the head as moved when its size or the countersignature's time changes, measured on its own clock,
     so no clock is compared across machines. A beat adds no link and changes no history: safety is as before (the
     beat is the "lost answer asked again" the witness already took). A beat at a size the witness no longer holds is
     refused (409), and the next tick deposes that node.
   - If the active is gone, the standby's append wins and it is active.
   - An old active that wakes up is refused at its next append. A refusal above its last committed size means it was
     deposed: it drops its uncommitted tail and resyncs as a standby, never "broken". A conflict at or below that size
     stays a fork alarm, as in 0.27.0. It drops its tail only after a verified fetch of the witness's countersigned
     checkpoint; a failed fetch means retry, never drop.
8. **Detection witnesses see only committed checkpoints.** Any C2SP witness may countersign for detection, but in HA
   mode it is sent only checkpoints the commit witness already took, so it can never hold a fork that halts a new
   active. Desks compare the heads their nodes and edges echo with the committed head, and a deployment may require one
   detection cosignature before a head is acted on, which limits what a compromised commit witness can do alone.
   Built 2026-11-05: in HA mode only the active node sends detection witnesses a checkpoint, at the committed size and
   its root; a standby, or a node deposed with a committed size it remembers, sends nothing. Desks hold committed links
   only (point 6), so the heads edges echo are compared with the committed head by construction. The optional
   requirement of a detection cosignature before acting is not built in 0.28.0.
9. **The commit witness never goes back.** It persists before answering, holds an exclusive lock on its state
   directory, and serves its countersigned checkpoint at once; C2SP's monitor endpoint may lag an hour, the commit
   witness's may not. It is never restored from a backup. After a loss its owner re-seeds it (`reset --seed SIZE ROOT`)
   from the newest head the desk saw echoed or answered, with a two-person confirmation; it never forgets the log and
   starts from nothing.
10. **Break-glass, when the commit witness is lost.** The security officer and a root trust owner sign a statement that
    names one signer and the base (the newest head the desk saw), at that signer's terminal, after the commit witness is
    stopped. The named signer then signs unwitnessed from that base; consumers accept its heads only from the base
    upward, and refuse any later countersigned head above the base. It follows no witness meanwhile, and a restore of it
    resumes at the newest head consumers acted on, by the 0019 procedure. It is an incident. HA comes back by seeding a
    commit witness from that signer's head. Built 2026-11-05 as the HA change of mode `break_glass`: it removes the
    `ha` record, names the node, its base is the link's own seq and prev, and it is refused while the commit witness
    still answers.
    The desk's side, 2026-11-05: an HA change link (off, break-glass, another commit witness) is signed with no
    countersignature to cover it, so a desk adopts it at exactly the next position without one, then follows under the
    configuration it sets; a break-glass link is noted once as a finding in the desk's activity log, which the
    officer's view and the SIEM export carry.
11. **Who signed is on record.** Each link names the signer node in its entry, and a takeover link says "took over at
    size n", as an edge's activation does (point 2). The records key on two hosts doubles where it lives; its escrow
    covers both, and rotation is 0030 point 1 (0.29.0).
12. **Without HA, nothing changes.** No `ha` head record: one signer, signing as in 0.27.0, the witness optional for
    detection, consumers as today. Nothing new runs, and a one-node edge stays one node.

## The model (point 4 to 10)
`docs/specs/SignerFailover.tla`, for TLC, and `tools/model_signer_failover.py`, which explores the same transition
system exhaustively. In both:
- **Actors:** two signers sharing the records key, which may sign anything at any time, crash, recover and be restored
  to an older state; the network delays, drops, duplicates and replays submissions; a break-glass switch; a witness
  reset.
- **Invariants:** OneHistory (never two histories acted on), ActedCommitted (in witnessed mode, every head acted on or
  answered is committed) and Takeover (a standby that is up can always get the committed links and append).
- **Step property:** CommitOnlyGrows (the committed head never goes back, but at a reset).
- **Results:** the design holds over every reachable state at two bounds:
  - two links, two submissions in flight: 2,099,832 states;
  - three links, one submission in flight: 1,367,712 states.

  TLC (version 1.8.0) checked the full bound, three links with two in flight: 9,479,224 distinct states, no error,
  every invariant and CommitOnlyGrows included; it also found each broken assumption's counterexample, on the same
  property the explorer did.
  Each of six broken assumptions yields a shortest counterexample:
  - consumers acting on uncommitted links;
  - a witness restored from a backup;
  - a check and write in two steps;
  - a witness without the links' bodies (takeover fails);
  - break-glass without stopping the commit witness (two histories);
  - a reset to an empty log.
- **The first run of the design itself failed:** after break-glass, the named signer could follow the stopped witness
  and sign a second history. That is why point 10 says it follows no witness.
- **Limits:**
  - Bounded: two signers, three links, two submissions in flight.
  - The witness is abstracted as one atomic store.
  - The edges' election is the edge implementation's and is not modelled here.
  - TLC needs Java and the TLA+ tools, so the suite runs the explorer at small bounds; TLC runs by hand with the
    command at the top of each configuration.

## Adversarial review findings and where they are answered
| Finding (2026-11-04) | Answer |
|---|---|
| Leases, terms and clocks: a resumed host acting on a lapsed lease, terms reissued after a witness restore | the first draft's grants are gone: the compare-and-swap needs neither (prior art) |
| The witness never saw the fence; links acted on before anyone refused them | points 4 and 6: the commit is the witness's compare-and-swap, and only committed heads are acted on |
| A standby without the committed links (H2) | point 5; modelled (`NoBodies` fails) |
| Consumers act on uncommitted links today (H3) | point 6 (a work item); modelled (`ActOnUncommitted` fails) |
| Lost answers (M4) | point 4: outcome unknown, asked again, the equal-size answer confirms |
| Losing a race read as a fork, the signer stops (M5) | point 7: deposed above the last committed size, a fork alarm below |
| Break-glass while the old active runs (H7) | point 10; modelled (`UnfencedBreakGlass` fails) |
| A reset accepts any history (H8) | point 9: re-seed only; modelled (`ResetEmpty` fails) |
| Detection witnesses holding a fork (H9) | point 8: they see only committed checkpoints |
| No attribution between signers (M10) | point 11 |
| A compromised commit witness (M11) | point 8: desks compare echoed heads; optional detection cosignature |
| HA inferred from absence (M12) | point 3: signed realm configuration |
| Flapping, equal-size "takeover", lagging monitor endpoint (M13) | points 7 and 9 |
| The liveness check proved nothing (H1) | the Takeover invariant now fails when the links cannot be fetched |

## Consequences
- In HA mode each change waits one round trip to the commit witness, and with the witness lost nothing commits until
  it is re-seeded or two people switch to break-glass; access is unaffected throughout.
- The commit witness is a third host, or the site's small device under DDIL, as qnetd is for a two-node cluster.
- Edges elect by the edge implementation's quorum and only report how they became active; the core uses the commit witness. Two
  mechanisms, one rule: a standby becomes active only when a third party agrees, never on its own timer alone.
- Work items for 0.28.0: the `ha` head record; the commit witness's body store, seed reset and immediate checkpoint;
  consumers adopting only committed heads; deposed versus forked in the signer; the signer node in each link's entry;
  the break-glass statement and its base; edge protocol 1.5's `activation`.

## Changelog
- 2026-11-04 Created as proposed (a term granted by the witness, with leases); the maintainer chose the witness and
  both sides in 0.28.0.
- 2026-11-04 Revised after its adversarial review, a prior-art study and the maintainer's footprint rule: the witness's
  compare-and-swap is the commit point; no leases or terms.
- 2026-11-04 Revised after the second adversarial review: link bodies at the commit witness, consumers on committed heads only,
  deposed versus forked, break-glass with a base and a stopped witness, re-seeding, detection order, attribution, HA as
  signed configuration; the model extended to all of it, and cited prior art and standards.
- 2026-11-04 Accepted: TLC checked the full bound (9,479,224 states) and the six broken assumptions.
- 2026-11-05 Who changes HA after the seed: the security officer and a root trust owner together (operator); the HA
  change link and the break-glass built.
- 2026-11-05 Point 6 built on the desk's side: desks check the commit witness's countersignature themselves.
- 2026-11-05 Point 8 built on the signer's side: detection witnesses see committed heads from the active node only.
- 2026-11-05 Point 10 on the desk: HA change links adopted at the next position, a break-glass noted as an incident.
- 2026-11-05 Point 7 amended: the active's beat at the commit witness (the first soak found the nodes handing over at every hold time on an idle realm).
