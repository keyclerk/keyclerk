# Changelog

Each release's notes come from its section here. Earlier entries are the releases' own one-line summaries;
the decision records (docs/decisions) hold the reasoning.

## 0.27.0 (2026-11-04)
- A restore no longer brings back what was erased: `keyclerk.backup take` writes a signed erasure journal (erased visit
  ids only) beside each manifest, `keyclerk.backup erasures` refreshes it, and a desk is restored only with a journal
  at least as new as the backup. `restore resume` and the new `restore leave` (a desk on the change log) erase again
  what it lists before the desk serves (decision 0028 point 6).
- A signer restored from a backup signs no change until `restore recover-log` or the restore link has run, so it
  cannot sign at positions it lost.
- A backup of a desk on the signed YAML store was refused: its records signature was taken for a key. Fixed.
- Behind a reverse proxy the public scan budget is kept per client: `api.trusted_proxies` lists the proxy networks
  (empty by default), and only from a listed proxy does the desk read `api.forwarded_header` (`x-forwarded-for` or
  `forwarded`), taking the rightmost address that is not a listed proxy (decision 0029 point 7).
- The configuration is refused when `backup.retention_days` is longer than `store.view_log_keep_days`, so a backup
  never keeps a look the desk has deleted (decision 0029 point 3).
- A witness for the change log (decision 0022 point 5, `keyclerk/witness.py`): the signer sends each new checkpoint,
  as a C2SP signed note, to the witnesses in the new `witness` configuration section, with a consistency proof from
  what each last countersigned. A signer restored from an older backup, rollback mark included, stops signing when a
  witness proves by its own countersigned checkpoint that the signer is behind or holds another history; an unsigned
  answer never stops it. `python -m keyclerk.witness serve` is a small C2SP witness, and any C2SP witness works.
  An unwitnessed link becomes a readiness incident after `witness.incident_after_minutes`, and
  `witness.block_after_minutes` can block signing; it is unset by default, so a site cut off from its witness keeps
  working. New metrics: `keyclerk_witness_total`, `keyclerk_unwitnessed_seconds`.
- The officer's ceiling judges a lease by its hours rounded up (edge protocol 1.4), at the desk and in the edge's
  verifier: rounded down, a lease up to 59 minutes longer than `max_lease_hours` passed.
- The reconciler sees child groups under a managed group: on Keycloak a member of one is under the managed group in
  every token, yet was not read (review row E5, reproduced on Keycloak 26.8.1). Their members are now removed through
  the admin API and logged out, the child group itself kept, and each child group is a finding on the run.
- A guest of a visit sees their own entry in full and only the names of the other guests: not their vehicles,
  kit, badges or gate times (decision 0009). The host, the organiser, escorts and the front office see the visit whole.
- The reconciler signs the identity broker's high-water mark with its own key (`--mark-key`). A mark that does not
  verify, or records older than it, refuse the revision, but memberships the records never required are still removed
  and the run reports an incident, so a mark written in the broker by hand can no longer stop every removal.
- A write about something that does not exist gets the same refusal, in the same words and with the same next
  step, as a write about something that is not the writer's; only the root and the security officer get the plain
  answer. Authority is checked before an ended membership or a visit's attendees are mentioned.
- Every preview leaves a line in the activity log (`outcome: preview`, with what a change would have answered);
  previews are left out of `keyclerk_changes_total`.
- The view log never loses a look: a full `views.log` rotates to a kept archive (`views-<UTC time>.log`) instead
  of dropping its oldest lines, and archives are deleted after `store.view_log_keep_days` (default 400).
- **Upgrading:** `approvals.acr` is required (decision 0030 point 5): a 0.26.x configuration without it is refused
  at start, saying so. Run `python -m keyclerk.init acr --keycloak URL --realm REALM --config FILE --write` to add
  the realm's strongest published level once you confirm it, or write `acr: none`, which the desk and the signer
  report as a finding at every start (docs/install.md, "The sign-in level of an approval").
- **Upgrading:** the reconciler needs `--mark-key` (docs/install.md, "The reconciler's high-water mark"); run it
  once with `--adopt-mark` to sign the mark an earlier version left.
- Backup and restore drill: `python -m keyclerk.backup take` copies a running desk and its signer through SQLite's
  online backup and verifies the copy (each change log against the records key, the full check, the signer's audit
  chain). It streams through a private staging directory, leaves out every key and the replicas an earlier resync
  replaced, and encrypts the copy with age to the recipients the configuration lists (`backup.recipients`, at least
  two custodians), with a signed manifest. `shipped` records where and when a copy went off-site.
  `check` and `restore` check the manifest first and refuse a copy that does not match it; a restored desk starts in
  restore mode. `drill` restores the newest good backup into a scratch directory and reports the recovery time.
  New `backup` configuration section and metrics `keyclerk_backup_age_seconds`, `keyclerk_backup_drill_failed` and
  `keyclerk_backup_recovery_seconds`.
- Restore safety for the signed YAML store: `python -m keyclerk.restore` puts a restored desk in restore mode (no
  writes, not ready, edges answer 503 and keep their bundle) and resumes it above a high-water mark the security officer
  and a root trust owner confirm by signature, so no revision number or edge bundle serial is signed twice
  (docs/install.md, "Restoring a desk from a backup").
- Signed snapshots of the change log (`kc-snapshot-v1`, `keyclerk/store/snapshot.py`): the signer writes one to
  `state/snapshots` after each passing background full check when the log has grown, keeping the newest two. A store
  adopts a snapshot only while empty and only with the links up to it, each checked as an append checks it; the
  root, head and fence they reach and the state file's hash must be the snapshot's, so a snapshot spares the rebuild,
  never the history. A follower's resync can start from one, and refuses one that is not the signer's log.
- Audit events for a SIEM (#29, `keyclerk/siem.py`): the desk's signed activity log as OCSF 1.3.0 JSON. With
  `siem.reader_token_file`, the management listener answers `GET /audit/events?after=SEQ` to that token only; the
  cursor is the log's line number, so a reader gets every event once across a restart. `python -m keyclerk.siem
  forward` sends RFC 5424 syslog over TLS to `siem.syslog`, trusting only its `ca_file`, and resumes from a cursor
  that moves only after each message is written. Each event carries its line's chain position, signature and
  records revision; people are pseudonyms and refusals carry reason classes, not text.
- The change log's signer, restored from an older backup, takes its lost links back from a follower whose chain
  verifies and starts with the restored one (`python -m keyclerk.restore recover-log`), so it never signs at a
  position it lost; a follower that forked is refused.
- The change log has a restore link: when no follower holds the links a restored signer lost, it appends one link
  with no ops whose `restore` part names the confirmed mark and the proofs of the security officer and a root trust
  owner, and the numbering resumes at mark + 1 (`python -m keyclerk.restore link`; new log conformance vectors).
- A desk fetches the signer's snapshot (#28): the signer protocol gains `snapshot` (the newest signed snapshot) and
  `snapshot_state` (its state file a megabyte at a time), and a follower's resync starts from it when the signer
  has one, every link before it still checked and the state's hash compared, else from the genesis as before.
- Privileged roles granted in the broker around KeyClerk are findings (#29): the reconciler reads the realm's
  role-mapping admin events from a cursor and reports every `realm-management` role and every role named in
  `reconcile.privileged_roles` mapped to a user or group directly, with who made it. The desk notes each once in
  its signed activity log, for the security officer's broker view and the SIEM. Report-only: nothing is removed.
- A SOAR proposes protective changes only (#30): with `soar.protective`, its API client may suspend a person, end a
  membership or raise a situation level through its registered feed, never grant or approve. Each change is checked
  and signed like any other, authored by the SOAR's workload; it waits for the security officer, the root or a
  person on call where policy says so, when it touches a person on call, and past `max_per_hour`, which also
  records a finding. A feed raise the engine would cap is refused with the reason. The person view lists a person's
  suspensions.
- Approvers are reminded, never handed an action (#30): the desk writes `approval_waiting` when it first sees a pending
  change, `change_expiring` when it has `approvals.remind.expiring_hours` left (24) and `approval_escalated` after
  `approvals.remind.escalate_after_hours` (72, naming the root and the security officer too), each once, in its signed
  activity log. Each names the change and its next approvers and carries no link or code that approves.
- SOAR webhooks (#30, `keyclerk/soar.py`): `python -m keyclerk.soar forward` sends the event types each endpoint in
  `soar.webhooks` chose as CloudEvents holding the SIEM's OCSF event, signed per Standard Webhooks, at least once and in
  order per endpoint; a failing endpoint retries from where it stopped and holds no other's queue. Reminders name their
  approvers as pseudonyms, or as broker ids for an endpoint configured to route them to people. Off unless configured.
- An edge reports a bastion taking away a lease's assignment before the lease expired, on any bastion: the
  `lease_ended_early` incident names the lease, and the desk accepts it only for a lease of the edge's last bundle
  ended before its expiry (edge protocol 1.4, decision 0029 point 8).
- Edge protocol 1.4 report members, each optional (#31): the bundle carries the records head it was cut from and the
  edge echoes it, and the desk raises an incident when an edge applied records newer than it holds or a head its
  change log does not hold; removal confirmations per lease are kept (the first of each); an edge declares what its
  bastion enforces by itself (`bastion.capabilities`, unknown tokens kept apart, never refused); an evidence entry may
  name the lease its session ran under. The reference agent (`edge_cli`) echoes the head.
- Backup hygiene (decision 0019 point 2): `python -m keyclerk.backup escrow challenge` encrypts a fresh value to
  each recipient that matters, retired ones a kept backup needs included; a custodian opens theirs with the age tool
  and `escrow answer` records the signed proof. `backup hygiene` reports a key not shown within
  `backup.escrow_check_days` and a recipient in use past `backup.rotate_after_days`; new gauges
  `keyclerk_backup_escrow_unproven` and `keyclerk_backup_recipients_due_rotation`.
- The repository meta for working in public: changelog fragments (`changelog.d/`, `tools/changelog.py`), a
  public text check on everything posted (`tools/public_text_check.py` and its workflow), ROADMAP.md, CODEOWNERS, a
  code of conduct, governance, maintainers, support and name-use pages, and a time limit on every CI job.
- A restore's mark has sources (decision 0019 point 5): `python -m keyclerk.restore status` proposes the newest
  revision anyone saw from the records heads edges echoed while the desk was in restore mode (edge protocol 1.4)
  and, with `--witness`, from the witness's countersigned checkpoint, both signatures checked. Two people still
  confirm the mark.

## 0.26.3 (2026-10-26)
- The image's trust store leaves out the emSign roots that certifi 2026.10.19 dropped after the eMudhra intermediate
  key incident (emSign ECC Root CA - G3, emSign Root CA - C1, emSign ECC Root CA - C3), so the desk, the reconciler
  and the signer never accept a server certificate chaining to them; the base image's Python (3.12.15) does not
  reject the affected intermediates itself yet. `tools/distrust_cas.sh` does it, in the Containerfile and in CI;
  `tests/test_trust_store.py` checks it. Dependency installs were already safe: every one is hash-locked.
- 0.26.2 was tagged internally only; its section below is part of this release.

## 0.26.2 (2026-10-26)
Hardening after a review of the change log, the identity boundary and the reconciler (decision 0028, 2026-10-26):
- The checking signer has a second listener for the reconciler (`--reconciler-listen`, `--reconciler-token`), the only
  one that records a broker subject; the desk's listener refuses `link_subject`. **Deployments on the change log:**
  start the signer with `--reconciler-listen` and point the reconciler's `--signer` at it, or accounts are not linked
  to their subject (access still works by anchor attribute, as in phase 1).
- The reconciler links a subject only on an applying run, only for a membership the records want, and only when one
  account carries the anchor attribute; a removal removes the member the read found, so a copy of an anchor on another
  account never blocks it.
- The signer refuses a mapping row that carries a subject or an identity provider id starting with `sub:`, refuses
  `sub:` anchors, and checks a link's entry shape (no free text, no provider ids).
- A follower refuses a resynced log that does not extend the history it verified.
- Approvals recorded on situations, surge packages and leases need a proof (or a pin in
  `approvals.accepted_without_proof`), like every other approval.
- A proof whose token was erased is reported as such instead of failing the check.
- The reconciler's removal cap counts every anchored member when it has no earlier desired set (a first run or a
  lost state).
- The desk: a refused approval names approvers only to someone the pending view shows them to; the public scan
  budget forgets quiet addresses, so a full table never refuses everyone.
- Edges: a lease credential is relayed only to the holder of that lease; a rotation meets the enrolment's rules for its
  keys and officer; the address endpoint answers only what the officer's ceiling and independence allow at the time
  of the request.
- Edges: after a rotation to another officer or key, the previous officer's ceiling governs nothing (no leases, an
  incident) until the officer in force signs one.
- An approval that does not count as a key the change needs is refused, with the reason that names why (`X does
  not count: ...`), and the change waits as it did. Before, such an approval answered `pending` and was kept: a key
  that does not count only adds that tail to the reason it leaves open, and the desk took the changed text for
  progress, so the approver saw nothing change and no why.
- Dependencies: wasmtime 50.0.1 (the runtime the compiled policies run in), jsonschema 4.26.0, cffi 2.1.1,
  pycparser 3.12, rpds-py 2026.9.1; for tests pytest 9.1.1 (a tmpdir handling fix) and hypothesis 6.170.6. The image's
  hash-locked `requirements.lock` is regenerated from `constraints.txt` with them.

## 0.26.1 (2026-10-25)
- The compiled policy modules no longer carry the build machine's folders: the compiler kept each source's absolute
  path for its error locations, so a module named the folder it was built in and its bytes, which edges pin by hash,
  depended on where it was built. `tools/build_policy.py` now builds from the policy folder by file name, and the
  modules are rebuilt; only their hashes change (the edge conformance set's `modules`), not what they decide.
- The leak gate reads binary files too (local paths, keys, tokens, personal names), and skips tool caches.
- `docs/references.md`: the standards KeyClerk implements, the conventions it follows and the software it stands
  on, each linked, and checked by a test.

## 0.26.0 (2026-10-25)
The desk runs on the signed change log, and a running deployment can move to it (docs/migrate-to-change-log.md). A
YAML deployment that does not move is unchanged.
- The configuration chooses the desk's store (`store.kind`: `yaml`, the default, or `sqlite`, the signed change
  log, which needs the checking signer), and the desk reaches its store through one protocol
  (`keyclerk.store.desk_store.DeskStore`). The migration command no longer needs `--preview`.
- The checking signer, for a desk on the change log: a change proposed again after its answer was lost is answered
  with the link it already is, never applied twice; the mapping rows of new people enter only with the commitment a
  record of the same change carries, and never re-point a mapped anchor or account; a log can start empty (op
  `start`), its first change judged whole; a frozen signer still serves the reads a desk follows by.
- The desk on the change log (`keyclerk.store.log_desk.LogStore`): it proposes every change through the checking
  signer and follows its log, keeps visits in its replica's side tables, rebuilds a lost replica from the signer,
  and resyncs into a new file. The desk and visit test suites run on both stores.
- Identity on the change log (decision 0028): an accounts record per internal anchor vouches for every mapping row,
  persons or not (persons and leases no longer carry commitments); sign-in, requests and committed documents are
  translated to internal anchors at the desk's boundary; the signer refuses a link that names a person otherwise; a
  link keeps an entry's structure, never its free text. A visit timer's suspension was refused on the change log
  because the timer was taken for a person: the engine's own actors are never re-keyed.
- The reconciler on the change log (`--log-replica`, `--signer`, `--records-key`): it follows its own replica of the
  log, verified against the records key it pins, and refuses a mapping row the log's accounts records do not vouch
  for and a plan naming an account the mapping does not; it tells the broker its own names, links each account it
  sees to its broker subject (signer op `link_subject`, once, audited) and from then on addresses it by that
  subject, never by the anchor attribute; an attribute moved to another account names nobody. Erased mapping rows
  leave every replica.
- Edge protocol 1.3 (decision 0028 point 5): the address leaves the bundle (a lease's `email` is null) and an edge
  fetches it when it sets a gateway credential, `GET /api/v1/edge/lease/{lease_id}/email`, a sealed
  `kc-edge-email-v1` for a lease in the edge's last bundle and live now, bound to the request's nonce, six a minute
  per lease; `edge.verify_email` is the reference and the conformance set has an `email` family (the address by
  its digest). A lease's `person` is opaque: KeyClerk's internal anchor on the change log.
- Migrating a running desk (`python -m keyclerk.store.migrate STORE STORE/log.db --signer ...`): the replica is built
  where the log store opens it, pending changes are re-keyed and can still be approved, the YAML-era activity log is
  moved aside, and the history starts with one line, migrated from signed YAML revision n. The runbook, with the way
  back and the purge checklist: docs/migrate-to-change-log.md.
- Health of the desk on the change log: it follows the signer every 15 s; readiness says when it cannot follow
  (not ready, with the reason) and when signing is frozen (ready, read-only); `keyclerk_log_breaks` counts follow
  failures, `keyclerk_signing_frozen` and `keyclerk_timer_refused_total` are new. A stale write is refused whole and
  says to look again; with the signer down reads go on and writes are refused, never queued; a desk that stopped
  between a link and its activity line writes the line at its next start; a replica restored newer than its
  signer is refused, and a refused start releases its lock. The fault model, with a test per row:
  docs/testing/concurrency-and-state-machines.md.
- The desk on the change log judges a change on what it reaches, as the signer does: one shared function
  (`store/working.scoped_judgement`) over its replica with the change tried and rolled back (`SqliteStore.trial`),
  the full check only when a change reaches everyone; it commits the ops it judged, moves its records forward by
  each link, and syncs the mapping in one transaction. At 20,000 employees a desk change takes 3.4 s instead of
  47 s (docs/testing/realistic-load.md); `tools/bench_org.py` names people by internal anchors again (`--desk N`).

## 0.25.1 (2026-10-25)
- The package version agrees with the release again: 0.25.0's `pyproject.toml` still said 0.24.1, so an install
  from the v0.25.0 tag reported itself as 0.24.1. Use 0.25.1; a test now holds the two versions together.

## 0.25.0 (2026-10-25)
- The signed change log on SQLite (decision 0022): signed links in a hash chain, a checkpoint per change, the checking
  signer's own replica, migration from the signed YAML store (refused with the fixes when its last revision has engine
  errors), changes judged on the records they reach with a background full check that compares. A YAML deployment is
  unchanged: migrating to the change log is offered from 0.26.0, with the desk on the store; until then the migration
  command refuses without `--preview`.
- Internal anchors (decision 0028): the migration re-keys every person to a random internal anchor before the genesis,
  with a salted commitment in the log and the identity provider's id only in erasable mapping tables, so no identity
  provider's id enters the chain; proofs on the change log resolve through the mapping, in two phases toward the broker
  subject.
- Realistic load measured (`tools/bench_org.py`, `docs/testing/realistic-load.md`): at 20,000 employees and 5,000 groups
  a change takes 0.4 to 1.8 s, after two fixes (the subtree rate bucket per start day, the group map once per check).
- The edge bundle names the roles KeyClerk governs on the edge (decision 0025, edge protocol 1.1); an edge may wait for
  its next bundle (decision 0026, edge protocol 1.2); signed-request conformance vectors; the protocol's references.
- `keyclerk init` writes admin personas on a privileged top group.
- Engineering: ruff, REUSE compliance, hash-locked CI tools, ClusterFuzzLite fuzzing of the bundle verifier, the public
  repository baseline, decisions 0025 to 0028.

## 0.24.1 (2026-10-24)
- edge-era changes approvable with required proofs; relicensed to EUPL-1.2

## 0.24.0 (2026-10-24)
- the checks scale (0017), approvers without a full check per person, health, readiness and metrics (0018 H1 to H3)

## 0.23.0 (2026-10-24)
- one signing mode (0014d), modules by hash, kc-unlock-v2, bound ended notice

## 0.22.0 (2026-10-23)
- integer bounds, horizons, vectors, lease e-mail, stable from

## 0.21.2 (2026-10-23)
- edge verifier refuses, never raises

## 0.21.1 (2026-10-23)
- UI review fixes

## 0.21.0 (2026-10-23)
- TPM attestation for edges (decision 0016)

## 0.20.0 (2026-10-23)
- the checking signer and proposer proofs (decision 0015)

## 0.19.0 (2026-10-23)
- edges ready for a pilot (0014c) and the final UI pass

## 0.18.0 (2026-10-23)
- the edge trust model (0014a), what an agent needs (0014b), the interface and CLI

## 0.17.0 (2026-10-23)
- edges (decision 0014)

## 0.16.4 (2026-10-23)
- the desk UI upgrade complete (slices 4 to 6)

## 0.16.3 (2026-10-23)
- desk UI slices 2 and 3, the person graph placed by rules

## 0.16.2 (2026-10-23)
- desk UI slice 1 (foundations and accessibility), panels never show "null", retired memberships judged as made

## 0.16.1 (2026-10-23)
- the persona rule is enforced by default; a retired membership is not judged on who its member is today

## 0.16.0 (2026-10-23)
- visits outside the signed records, one fold per check, honest README

## 0.15.0 (2026-10-23)
- admin personas, change 1: every effective member judged, KeyClerk's own powers by account (decision 0011a)

## 0.14.0 (2026-10-23)
- personas, workloads and agents (decision 0011); API hardening found by fuzzing the contract

## 0.13.1 (2026-10-23)
- visit requests pass the API contract (attendee objects no longer require every field); an API-level test registers a visit; use case extended with two security firms, one federated (G12-G18)

## 0.13.0 (2026-10-23)
- person-first visits (decision 0010)

## 0.12.0 (2026-10-23)
- visit badges, a RESTRICTED badge signed out by two people (decision 0009)

## 0.11.0 (2026-10-23)
- the visit QR code and the phone scan (decision 0009)

## 0.10.0 (2026-10-23)
- visits, first slice, decided by a compiled visits policy (decision 0009)

## 0.9.0 (2026-10-23)
- the delegation tree, decided by a compiled tree policy (decision 0009)

## 0.8.1 (2026-10-22)
- every records kind survives a split; split files never carry YAML aliases

## 0.8.0 (2026-10-22)
- persona graph

## 0.7.1 (2026-10-22)
- free the compiled policy in order at exit (no access violation in wasmtime teardown)

## 0.7.0 (2026-10-22)
- second-key standing

## 0.6.3 (2026-10-22)
- the front end redesigned for clarity; second keys from the organisation only

## 0.6.2 (2026-10-22)
- fixes from an independent review

## 0.6.1 (2026-10-22)
- every failure says why, what completes the intent, and who can do it

## 0.6.0 (2026-10-22)
- use what the broker offers (decision 0007)

## 0.5.0 (2026-10-22)
- approvals as the approver's own signature (decision 0006)

## 0.4.6 (2026-10-22)
- the API page never prints the CSRF token; wider change cards

## 0.4.5 (2026-10-22)
- an API page built from the contract; need-to-know reads

## 0.4.4 (2026-10-22)
- conflicts, concurrency, interruptions and damaged state

## 0.4.3 (2026-10-22)
- the live desk attacked over HTTP, and what that found fixed

## 0.4.2 (2026-10-22)
- front end fixes from the first browser walk; refused attempts logged

## 0.4.1 (2026-10-22)
- the history guard compares times by meaning; a manager's key makes a change wait

## 0.4.0 (2026-10-22)
- the desk, its API contract and a front end (decision 0005)

## 0.3.1 (2026-10-22)
- a run whose log cannot be written is still reported and fails

## 0.3.0 (2026-10-22)
- hardened input and output at every seam; an adversarial review's findings dispositioned

## 0.2.0 (2026-10-22)
- the reconciler loop, the read-only console and the container image

## 0.1.3 (2026-10-22)
- Keycloak 26.8.1 as measured in the first end-to-end run

## 0.1.2 (2026-10-22)
- no review identifiers of a deployment in code, Rego or tests

## 0.1.1 (2026-10-22)
- the Rego ships inside the package

## 0.1.0 (2026-10-22)
- the engine, configuration-driven and named for no deployment
