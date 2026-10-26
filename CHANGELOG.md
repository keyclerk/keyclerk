# Changelog

Each release's notes come from its section here. Earlier entries are the releases' own one-line summaries;
the decision records (docs/decisions) hold the reasoning.

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
