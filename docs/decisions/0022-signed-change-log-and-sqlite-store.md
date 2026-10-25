# 0022. The signed change log as the source of truth, on SQLite

- Status: accepted (2026-10-24). Built in steps: the store, the checking signer's replica, scoped judging and the
  re-keying migration in 0.25.0; the desk on the store in 0.26.0 (released 2026-10-25), and migrating with it. See the
  amendments for what moved to later releases.
- Context: the target is 500,000 identities. After decision 0017 the checks are near linear (1,000 extra people in
  4.4 s, 5,000 in 29 s), but the records were one YAML document, loaded, validated, copied, checked and signed whole on
  every change. Measured at 5,000 people (85,000 memberships): 19 MB, parsing 14.6 s, schema validation 9.5 s, a deep
  copy 1.6 s, 116 MB in memory. At 500,000 that is about 1.9 GB and 40 minutes per load. Prior art shaped the choices
  below: midPoint's move to a PostgreSQL-only native repository; Teleport, OpenFGA and SpiceDB behind narrow datastore
  interfaces; Vault's integrated storage; tile-based transparency logs with signed checkpoints and witnesses. So did
  two adversarial reviews, one of them from the edge's side.

## Decision
1. **The signed change log is the source of truth.** Every change is a signed link in a hash chain; every store,
   backup and standby is a replay of it, checked against signed checkpoints. Signed snapshots, themselves checked
   against the log, spare a rebuild from replaying all history. The signer keeps its own replica, built only from
   links it signed, and never takes the state from the desk.
2. **One engine now: SQLite.** It is in the standard library: one file, no server. Each record is stored whole as
   canonical JSON with generated, indexed columns. The store interface stays narrow (append a signed link, get by key,
   range by index, snapshot). An in-memory reference store implements the same interface and runs the same tests, so
   the interface does not drift towards SQLite. PostgreSQL comes when someone needs it, as another replica. The store
   refuses network and sync filesystems (SQLite's write-ahead log needs one host), and the background full check runs
   on a snapshot, never on the live database.
3. **Personal data outside the log.** The log carries opaque anchors and no names in any reason; names and attributes
   sit in a mutable table keyed by anchor, so erasure is a delete and the history stays verifiable without pointing at
   anyone. Existing anchors and reason texts migrate. The scope includes the edge: bundles carry opaque anchors and keep
   e-mail out of long-lived edge state; erasure reaches edge logs, evidence and recordings under a retention policy,
   which is a decision of its own.
4. **No bulk path.** An import is split into ordinary changes, one per group, each through its approvals and checks; a
   dry-run import shows the changes and who must approve them. The migration from a signed YAML store needs no import:
   its genesis link verifies the last YAML revision's signature against the pinned records key.
5. **A checkpoint per change, witnesses on a timer.** The signer signs a checkpoint (log size, root) with every change.
   Witnesses co-sign the newest one every few minutes, and at once after a revocation. Checkpoint reads are
   rate-limited. The head an edge sees is an opaque, totally ordered, monotonic token: "behind" is normal, "backwards"
   is an anomaly, and the witness bounds how far behind.
6. **Before backup, the witness, signer high availability and publication,** so those are built once, on the log.

## Guards
- Scope: the checks scoped to what a change reaches are computed by the engine, never the caller, and the background
  full check compares the two. A verified integrity violation freezes signing; an incomplete or transient check retries
  and raises an alarm. A frozen signer never revokes edges: they run on their horizon.
- One writer: the signer appends; desks propose. Signer failover reuses decision 0013's model (a lease or a majority,
  plus fencing: a signer that loses the lease stops before another starts), with a fencing number in every link.
- The working set: a change loads the records its checks need into today's shape, so check code does not change. Done
  check by check, behind equivalence tests, as in 0017.
- A Merkle tree that ever becomes verifiable outside the signer is specified canonically, with vectors.
- Bundles stay per edge, guarded by a size test at 500,000 identities; serials stay per edge.
- Restore replays and verifies the chain from the genesis to the head, and checks the head against the witness.

## Amendments
- 2026-10-24, schema caps: the records schema's whole-document caps on how many records a kind holds (maxItems on the
  top-level arrays, for approval and proposal proofs 100,000) bound one YAML file read whole. Records kept one per row
  are judged without them, the background full check included, and the signer bounds each change instead: at most 500
  records of one kind per change, refused with the reason. The YAML path keeps the caps. A signer judging in full
  refuses a change when the records fail the schema, rather than judge nothing (the full check stops at schema errors).
- 2026-10-24, the background full check: it is linear and reads the whole records into memory. The likely direction is
  a streaming or partitioned check over the snapshot, each partition still compared with the scoped judgement, so memory
  stays flat and a run can spread over a day. Until it is built (0.26.x), the daily background full check is bounded
  at 50,000 people.
- 2026-10-24, the scope of 0.25.0: point 3 (personal data outside the log) moves to a release of its own, after the
  erasure decision; signed snapshots move to 0.27.0, with backup (decision 0019). 0.25.0 keeps the desk on the new
  store, its documentation and migration runbook, the import split into ordinary changes with a dry run, and
  rate-limited checkpoint reads with an opaque head token for edges.
- 2026-10-24: a migration whose last signed YAML revision carries engine errors is refused, listing each error with the
  ordinary change that fixes it. The genesis is judged, not only proven.
- 2026-10-25, a realistic organisation (`tools/bench_org.py`, `docs/testing/realistic-load.md`): 20,000 employees,
  5,000 groups, 1,000 agents, 5,000 workloads, birthright access from rules. Two causes of slowness were found and
  fixed. A membership's reach named its subtree's rate bucket for every day, so every membership change was judged in
  full; it now names its start days only. The group map was rebuilt for every membership; it is now built once per
  check. A change then costs 0.4 to 1.8 s, a new team (judged in full) 64 s, the background full check 64 s.
- 2026-10-25, history: after a year with nothing pruned (205,000 memberships) a membership change costs 4.5 to 7 s. So
  0.26.x leaves records that ended before a safety margin out of a change's working set, proven sound like the other
  scope rules, while the background full check still reads everything. With the erasure and retention decision,
  records past their retention move out of the current state into an archive; they stay in the signed log.

- 2026-10-25, the 0.25.0 cut: 0.25.0 is released with the store core, the checking signer's replica, scoped judging, the
  realistic-load fixes and the re-keying migration (decision 0028), but without the desk on the store. That step
  (the desk proposing through the signer and following the log, sign-in through the mapping, the reconciler on the
  log, idempotent proposals, the transient e-mail and the fault tests) is 0.26.0, and migrating a deployment is
  first offered then; later steps move one release on.

## Consequences
Trust no longer depends on the database; a second engine is a replica, not a second trust model. The edge wire is
unaffected while bundle, ceiling and ended notice stay signed by the pinned keys over their own bytes. Later steps on
the roadmap slip by about one release. The anchor migration is the largest piece of work outside the store itself.
