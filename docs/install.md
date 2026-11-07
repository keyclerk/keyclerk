# First run

A fresh KeyClerk install has no records, and nothing can be done from the desk without them. No desk action writes the
catalogue of entitlements, the realm's head (who holds the root role, who the security officer is) or the people the
records know, and creating a group at the desk needs a parent group that already exists. So the first records are
written outside the desk, once. `keyclerk init` writes that minimum, checks it with the engine's own checks and hands
it to the desk, which signs it as the first revision.

Init only bootstraps the first administrators. Every other person comes from the source of joiners (the identity
provider and the joiner feed the deployment connects), never from init.

## What init writes, and why

| Record | What it holds | Why it is needed |
|---|---|---|
| `realm.yaml`: `realm`, `home` | the realm's name and the home that masters its grants | every record belongs to one realm; the loader needs both |
| `realm.yaml`: `root` | the root trust owner (the first holder, from now on) and the security officer | the root is where every delegation starts; the security officer's key is the second key on the root's privileged changes, so the two are different people |
| `realm.yaml`: `persons` | the root, the security officer, optionally an edge officer and the entitlement's owner, each with their identity-provider anchor; when the top group is privileged, each anchor also states the persona purpose `admin` | the desk lets only a person the records know act; nobody can add the first person from inside. Power over a privileged group, and membership in it, take an admin persona (the persona rule, enforced by default) |
| `catalogue/<entitlement>.yaml` | one entitlement: its application, risk class (low, elevated, privileged) and owner | a group can carry only what is in the catalogue, set by the entitlement's owner |
| `groups/<group>.yaml` | one top group (no parent) carrying that entitlement, with its fixed class | the tree has exactly one top group, and every group the desk creates hangs under an existing one |
| `seed.yaml` | the same records as one file | the form the desk seeds from and signs; the reconciler reads one signed file, never a directory |

The directory form (one file per record) is the form to review and keep in a repository; `seed.yaml` carries the same
records as one file. Init reads both back through the loader and refuses if they differ.

Init refuses, with the reason and what completes the intent, when:

- the target directory is not empty (init never overwrites records; a realm that has records is changed at the desk);
- the root and the security officer are the same anchor;
- the edge officer is the root or the security officer (an edge's officer is never a core administrator, or a core
  administrator could widen an edge's ceiling);
- any value is not in the form the records take (anchors and identifiers in the narrow identifier set, a risk class
  from the three);
- the engine's checks refuse the result (the same checks the desk, the checking signer and the reconciler run: the
  records schema, identifiers, zoned times, duplicate ids, grants and the delegation tree). A top group whose fixed
  class is below the entitlement it carries is one example.

When it refuses, it writes nothing: the records are built and checked in a work directory next to the target and moved
into place only when every check passes.

## Running it

In a terminal, init asks for every value it is not given:

```
python -m keyclerk.init ./records --config keyclerk.yaml
```

For a scripted install, give every value as a flag and `--no-input`, so a missing value is refused instead of asked
for. None of the values is a secret: init holds no key and signs nothing.

```
python -m keyclerk.init ./records --config keyclerk.yaml --no-input \
    --realm example \
    --root idp:7c1f-root \
    --officer idp:31ee-officer \
    --entitlement admin-console --application keyclerk --risk privileged \
    --group all
```

| Flag | Value | Default |
|---|---|---|
| `--realm` | the realm's name: lowercase letters, digits and hyphens | asked |
| `--home` | the home that masters the realm's grants | the realm's name |
| `--root` | the root trust owner's anchor at the identity provider | asked |
| `--officer` | the security officer's anchor, another person than the root | asked |
| `--entitlement`, `--application` | the first entitlement and its application | asked |
| `--risk` | its class: low, elevated or privileged | asked |
| `--owner` | the entitlement's owner (the only one who may let a group carry it) | the root |
| `--group` | the top group's id: 2 to 63 lowercase letters, digits and hyphens | asked |
| `--group-risk` | the top group's fixed class | the entitlement's class |
| `--edge-officer` | an edge officer's anchor, never the root or the security officer | none |
| `--root-person`, `--officer-person`, `--edge-officer-person`, `--owner-person` | the person names in the records | `root-holder`, `security-officer`, `edge-officer`, `entitlement-owner` |

The configuration (`--config`, or `KEYCLERK_CONFIG` in the environment) is the one the desk will run with: the checks
read their roles and limits from it.

## After init

1. Review the records in the target directory. They are the realm's first revision.
2. Start the desk on an empty store with `--seed records/seed.yaml`. With `--signer` the checking signer signs the
   first revision; with `--signing-key` the desk signs it with the key in its own process (for development). The desk
   writes `records.yaml` and its detached signature `records.yaml.sig` as revision 1, the form the reconciler verifies
   with `--signing-key`. Unsigned records are never applied outside a local demo.
3. Sign in at the desk as the root trust owner and build the tree under the top group: subgroups, delegations, members.
4. Connect the source of joiners. People come from there; init is not run again for them.

From 0.25.0, the checking signer judges the first revision in full against an empty state, as it judges every later
change, and a seed that fails is refused with nothing signed. Before 0.25.0, the check init ran is what stands for the
first revision: seed the desk only from records that init (or the same checks) accepted.

When approval proofs are required (`approvals.proofs: required`), a seed's high-risk records need their proposer's own
proof, as every high-risk change does: the root signs the seed at the identity provider with a fresh sign-in, through
the desk's approval flow, before the first revision applies.

### Check a deployment before it starts
`python -m keyclerk.init check --config keyclerk.yaml --for signer,desk,reconciler,witness` validates the configuration
whole and names, for each service, the settings it needs; give a service's planned command line too
(`--reconciler-args "--keycloak ... --state ..."`) and it names every missing flag, missing file and rule between flags
at once, instead of one refusal per start. docs/deployer-contract.md lists what each service needs; it is generated
from `keyclerk/contract.py`, which a test keeps in step with each service's own command line.

### The sign-in level of an approval
From 0.27.0 the configuration names the sign-in level every approval proof must carry, `approvals.acr` (the broker's
`acr` claim); a configuration without it is refused. Let init propose it from the realm:
`python -m keyclerk.init acr --keycloak URL --realm REALM --config keyclerk.yaml --write`. It reads the levels the
realm publishes, proposes the strongest, and writes only the value you confirm. Keycloak publishes `0` and `1` until
the realm has a level-of-authentication flow; bind the level you require to a passkey there (Authentication, a flow
with Condition - Level of Authentication) so that an approval needs one. `acr: none` is accepted when written, and the
desk and the signer report it as a finding at every start: a password-only sign-in then approves as well as a passkey.

#### A Keycloak realm without a level-of-authentication flow
A fresh realm publishes only `0` and `1`, and its first sign-in with a temporary password reaches `1` as well. So
`approvals.acr: "1"` would let a password-only session approve; name the passkey sign-in as a level of its own
instead. The order matters: Keycloak refuses a default level its realm does not map yet (seen on 26.8.1).
1. Map a name to the level: in the realm settings, "ACR to LoA mapping" (the realm attribute `acr.loa.map`), add
   `passkey` -> `1`.
2. In the browser flow, put the passkey step (WebAuthn passwordless) in a conditional sub-flow whose condition is
   "Condition - Level of Authentication" with level `1`, so only a passkey sign-in reaches it.
3. Then, on every client people sign in through (the desk's and any approval client), set "Default ACR values" (the
   client attribute `default.acr.values`) to `passkey`.
4. In `keyclerk.yaml`, `approvals.acr: passkey`. `python -m keyclerk.init acr` now proposes it, and an approval from a
   password-only session is refused.
An installer or a realm managed as code does these steps in this order.

## Where the desk keeps the records
The desk keeps the records in the folder `--store` names. The configuration's `store` section chooses how: `kind:
yaml`, the signed YAML store and the default when the section is left out, or `kind: sqlite`, the signed change log
(decision 0022), from 0.26.0. On the change log the desk never holds the records key: start it with `--signer`.
Start the signer with `--reconciler-listen` too, and point the reconciler's `--signer` at that listener: it is the
only one that links a person to their sign-in account.
docs/migrate-to-change-log.md moves a running deployment over; a new deployment on the change log starts the signer
empty and seeds it from `--seed`, its first change judged whole. The YAML store suits up to a few thousand people; the
change log is built for organisations of tens of thousands.

## Sending audit events to a SIEM
The desk's activity log (every change, refusal, approval and edge event, each line chained and signed) is offered to a
SIEM as OCSF JSON, in two ways, each off until configured:

```yaml
siem:
  reader_token_file: /etc/keyclerk/siem-reader.token   # 32 characters or more, not the management token
  syslog:                                              # for python -m keyclerk.siem forward
    host: siem.example.org
    port: 6514
    ca_file: /etc/keyclerk/siem-ca.pem                 # the only CA trusted for the receiver
```

- **Pull.** With `reader_token_file`, the management listener answers `GET /audit/events?after=SEQ&limit=N` (at most
  500) to that token only: `{events, next, head}`. Keep `next` and ask after it: a restart of the desk loses nothing and
  repeats nothing, because the cursor is the log's own line number.
- **Syslog over TLS.** Run `python -m keyclerk.siem forward --store DIR --config FILE` as its own service, as the desk's
  user. It sends RFC 5424 messages over TLS (RFC 5425), trusting only `ca_file`, and keeps its place in
  `siem-syslog.cursor` in the store's directory (or `cursor_file`), which moves only after each message is written.
  After an outage it resumes there; a crash between a write and the cursor can send one event twice, so a SIEM
  removes duplicates by `metadata.uid`.

Each event carries the line's `seq`, `prev`, `sha256`, signature and records revision under `unmapped.keyclerk`, so the
SIEM's copy can be checked against the desk's signed log. People appear as pseudonyms (`person-pseudonym:SITE/...`,
keyed by `siem-pseudonym.key` in the store's directory, made on first use; keep it with the store's backups, since a
new key gives new pseudonyms), and a refusal carries the classes of its reasons, not their text; the `change_id` leads
back to the desk.

## Connecting a SOAR
Both directions are off until configured.

**Webhooks out.** `python -m keyclerk.soar forward --store DIR --config FILE`, as its own service, sends the event types
each endpoint chose: changes (`keyclerk.change.applied.v1` and the other outcomes), findings
(`keyclerk.edge.incident.v1`, `keyclerk.console.grant.v1`) and the approvers' reminders (`keyclerk.approval.waiting.v1`,
`keyclerk.change.expiring.v1`, `keyclerk.approval.escalated.v1`). Each is a CloudEvents envelope holding the SIEM's
OCSF event, signed per Standard Webhooks with the endpoint's secret; check it with any Standard Webhooks library.
Delivery is at least once and in order per endpoint. A reminder names the next approvers as pseudonyms, or as their
broker ids on an endpoint with `identities: anchors` that routes reminders to mail or chat. It never carries a link or
code that approves: the approver signs in to the desk.

```yaml
soar:
  webhooks:
    - url: https://soar.example.org/keyclerk
      secret_file: /etc/keyclerk/soar.secret
      events: [keyclerk.approval.waiting.v1, keyclerk.change.applied.v1]
  protective:
    client: soar-client          # its API client: list it in --api-client too
    workload: "wl:soar"          # a workload in the records (kind workload, with an owner): the author of its changes
    feed: soar                   # registered in the records' situation_feeds, with its max_level
    max_per_hour: 10
```

**Protective proposals in.** With `protective`, the SOAR's access token may propose three changes through the change
API and nothing else: `suspend_person` (`anchor`, `reason`), `end_membership` (`membership_id`, `reason`) and
`raise_situation` (`level`, `scope`, `reason`, through its feed, so at most one step above what people announced). Each
is checked like any change and signed when it applies, with the workload as its author; a suspension shows on the
person's view. A proposal waits for the security officer, the root or a person on call when `apply_at_once` leaves its
action out, when it touches a person on call, or when the SOAR has made `max_per_hour` changes in the last hour, which
also records a `soar_ceiling` finding. A SOAR never grants or approves, and lifting a suspension still takes two people.
Break-glass at an edge is reported as an incident that names no person, so it does not spare anyone yet.

## Behind a reverse proxy

The phone scan and the QR key need no sign-in, so the desk keeps a small budget of scans per client address. Behind a
reverse proxy every request comes from the proxy, and one busy phone spends the budget for everyone. List the proxies
in the configuration:

```yaml
api:
  trusted_proxies: [10.0.0.0/24]
  forwarded_header: x-forwarded-for     # or forwarded (RFC 7239): the one header your proxy sets
```

Only from a listed address does the desk read that header, and it takes the rightmost address that is not a listed
proxy: the address the proxy saw. Make the proxy append to the header, never pass a client's copy on alone. The list
is empty by default, so a desk without a proxy ignores the header.

## Taking backups and drilling the restore
`python -m keyclerk.backup` takes a backup only KeyClerk can make (decision 0019); your backup tool ships it.

1. Once per host: `python -m keyclerk.backup key --out backup.key` writes the manifest key and prints its public key.
   Put it under `backup.manifest_keys` in the configuration. Each custodian makes an age key pair with `age-keygen`
   and keeps the identity in their password manager. Make one more for the drill, kept on the drill host. List the
   custodians' recipients and the drill's under `backup.recipients`: a backup is encrypted to those and to no other,
   so changing the schedule's command line cannot add a reader (decision 0029).
2. On a schedule, while the desk and the signer run: `python -m keyclerk.backup take --desk DIR --signer-state DIR
   --records-key HEX --key backup.key --out OUTBOX`. Each store is copied through SQLite's online backup into a
   private staging directory and verified there: each chain is checked against the records key, the full check runs
   on the signer's copy, and the signer's audit chain is checked. The copy is then encrypted with age to every
   recipient. Only the encrypted file ever lands in `OUTBOX`, and memory stays small whatever the store's size. It
   leaves out every `*.key` file and names it in the manifest; a file that looks like a key under another name refuses
   the backup. It also leaves out replicas an earlier resync replaced. Escrow the keys apart.
3. Ship `OUTBOX` off-site to object storage with object lock. Retention and pruning are the shipper's
   (`backup.retention_days` states the target; the configuration is refused when it is longer than
   `store.view_log_keep_days`, so a backup never keeps a look the desk has deleted). Once a copy is off-site, the shipper records it: `python -m
   keyclerk.backup shipped --manifest FILE.manifest.json --where BUCKET/OBJECT --key backup.key` writes a signed
   `FILE.shipped.json` beside the manifest. Keep a copy of the manifests and shipped records where the desk can read
   them (`backup.manifests`): `keyclerk_backup_age_seconds` is the age of the newest shipped backup. Alert above
   `backup.max_age_hours`.
4. On a schedule, on a host that is not the desk: fetch the newest copy and run `python -m keyclerk.backup drill
   --from DIR --pin HEX --records-key HEX --identity DRILL_IDENTITY --report drills.jsonl`. It restores into a
   scratch directory, verifies everything again and reports the measured recovery time. Point `backup.drill_report`
   at the report: `keyclerk_backup_drill_failed` is 1 after a failed drill, which is an incident.

A custodian can decrypt a backup without KeyClerk: `age -d -i IDENTITY FILE.tar.age | tar x`.

### Proving the escrowed keys, and rotating them
A backup is only as good as the keys that open it. Every quarter (`backup.escrow_check_days`, 90 by default), prove that
each recipient's key is still held: `python -m keyclerk.backup escrow challenge --manifests DIR --pin HEX --key FILE`
writes one encrypted file per recipient in `DIR/escrow`, for the configured recipients and for every retired one a kept
backup still needs. Each custodian opens theirs with the standard tool (`age -d -i their-key.txt FILE`) and tells the
operator the value, who records it with `escrow answer --recipient AGE1... --answer VALUE`; the drill's test key
answers with `--identity`. `python -m keyclerk.backup hygiene --manifests DIR --pin HEX` reports a recipient whose
key was not shown in that window, and a configured recipient in use past `backup.rotate_after_days` (365 by default). To
rotate, add the custodian's new key to `backup.recipients`, and remove the old one once the backups encrypted to it
have aged out of `backup.retention_days`; until then hygiene keeps asking for its proof. The gauges
`keyclerk_backup_escrow_unproven` and `keyclerk_backup_recipients_due_rotation` count both.

## Restoring a desk from a backup
To restore from a backup taken as above, run `python -m keyclerk.backup restore --archive FILE.tar.age --manifest
FILE.manifest.json --pin HEX --records-key HEX --identity CUSTODIAN_IDENTITY --to EMPTY_DIR --erasures
NEWEST.erasures.json`. It checks the manifest before anything else (a trusted signature, then the archive's size and
hash) and refuses a copy that does not match, saying why. It checks every file, verifies the copy again, writes
`EMPTY_DIR/desk` and `EMPTY_DIR/signer`, and puts both in restore mode. Bring the keys it lists back from escrow, then
continue below.

A restored desk must never sign a revision number, or an edge bundle serial, that was already signed before the loss.
On the signed YAML store:

1. Put the store folder back from the backup (`keyclerk.backup restore` does this) and run `python -m keyclerk.restore start --store DIR`.
2. Start the desk as usual. It is in restore mode: it writes nothing, readiness says not ready, and edges get 503,
   which they treat as an outage: they keep their current bundle and run on their horizons. Each edge that reports
   leaves the bundle serial it applied (`python -m keyclerk.restore status --store DIR` shows them).
3. Find the newest revision anyone saw: `python -m keyclerk.restore status --store DIR` proposes one from the heads
   edges echoed while the desk was in restore mode, and with `--witness URL --witness-key VKEY --origin ORIGIN
   --records-key HEX --signer-state DIR` from the witness's countersigned checkpoint; weigh it against the reconciler's
   high-water mark and the last report you have. The
   security officer and a root trust owner each sign in at the broker with the nonce from
   `python -m keyclerk.restore nonce --store DIR --realm R --mark N --by ANCHOR` and save the ID token.
4. Stop the desk and run `python -m keyclerk.restore resume --store DIR --key KEY --realm R --mark N --proof
   OFFICER=FILE --proof ROOT=FILE --approval-issuer ... --approval-audience ... --keycloak ...`. It signs the records
   again as revision N + 1, raises each edge's bundle serial above what it applied, runs the full check and leaves
   restore mode. Revisions lost since the backup are logged as an incident: people propose them again.
5. Start the desk.

On the change log a revision number is a position in the signed chain, so a signer restored from an older backup
must not sign at the positions it lost (that would fork the chain). With the signer stopped, take the lost links back
from a follower: `python -m keyclerk.restore recover-log --signer-state DIR --from REPLICA_DB --records-key HEX`, where
`REPLICA_DB` is the reconciler's (or a desk's) `replica.db`. It verifies both chains, refuses a follower that forked,
appends each lost link with its signature checked, adds the proof tokens and anchor rows the follower holds, and
reports rows that differ for you to read. The signer seals a fresh checkpoint when it starts. When no follower holds the lost links, the signer appends a restore link instead: the security officer and a root
trust owner each sign in at the broker with the nonce from `python -m keyclerk.restore log-nonce --signer-state DIR
--key KEY --config FILE --mark N --by BROKER_ID`, then, with the signer stopped, `python -m keyclerk.restore link
--signer-state DIR --key KEY --config FILE --mark N --proof OFFICER=FILE --proof ROOT=FILE --approval-issuer ...
--approval-audience ... --keycloak ...` signs one link with no ops that resumes the numbering at N + 1. Followers
replay it like any link. A signer restored with `keyclerk.backup restore` refuses every change until one of the two
has run. Then start the signer and the desk, and take the desk out of restore mode: `python -m keyclerk.restore leave
--store DIR --config FILE --signer ADDR`. It checks that the desk follows its signer without a break, applies the
erasure journal, raises each edge's bundle serial above what it applied, and ends restore mode.

Backups forget what was erased (decision 0028 point 6). `keyclerk.backup take` writes an erasure journal
(`*.erasures.json`, the erased visits' ids only) beside each manifest. Refresh it after an erasure with `python -m
keyclerk.backup erasures --desk DIR --key backup.key --out FILE`, and ship it apart from the backups. A desk is restored
only with `--erasures FILE`, a journal signed by a trusted manifest key and at least as new as the backup. `resume`
(YAML store) and `leave` (change log) erase again what it lists before the desk serves.

## A witness for the change log
The signer's mark of what it signed lives in its own state, so a signer restored from an older backup brings back an
older mark too. A witness, run on another machine by another owner, keeps the newest checkpoint of the log it
countersigned and countersigns only checkpoints that extend it (c2sp.org/tlog-witness). From 0.27.0 the signer sends
each new checkpoint to the witnesses you configure, and stops signing when one proves, by a checkpoint it
countersigned, that the signer is behind it or holds another history. The signer never stops on the witness's word
alone, so an answer forged on the network cannot halt signing.

1. On the witness host, make a key (`python -c "import os; print(os.urandom(32).hex())" > witness.key`, readable only by
   the witness's user) and print the log's vkey from the records public key: `python -m keyclerk.witness vkey --type
   log --name ORIGIN --pub RECORDS_PUBLIC_HEX`. The origin names the realm's log, as a schema-less URL such as
   `keyclerk.example.org/realm`.
2. Run `python -m keyclerk.witness serve --key witness.key --name witness.example.org/kc1 --state DIR --log LOG_VKEY
   --listen 127.0.0.1:8098`, with TLS in front when it leaves the host. Print its own vkey with `python -m
   keyclerk.witness vkey --type cosigner --name witness.example.org/kc1 --key witness.key`.
3. In the configuration:

   ```yaml
   witness:
     origin: keyclerk.example.org/realm
     cosigners:
       - url: https://witness.example.org/kc1
         vkey: witness.example.org/kc1+...      # step 2's vkey
     incident_after_minutes: 30                 # readiness says unwitnessed after this
     # block_after_minutes: 240                 # unset by default: a cut-off site keeps signing
   ```

Any C2SP witness serves as well, and `quorum` asks that several hold a checkpoint before it counts. The signer checks at
start, after each signed link and every `every_seconds` (300 by default). `head` and the desk's readiness say how far the
log is witnessed and why a witness failed; `keyclerk_unwitnessed_seconds` measures it. After a restore the realm's
officers confirmed (above), the witness still holds the newer history and the signer refuses to sign. The witness's
owner then resets the log there, with the witness stopped: `python -m keyclerk.witness reset --state DIR --origin
ORIGIN --by NAME --reason TEXT`. The reset is kept in the witness's `evidence.jsonl` with the checkpoint it forgot, as
is every checkpoint the records key signed that the witness refused.

## Two signer nodes (high availability)
From 0.28.0 two to four signer nodes can hold the records key, one active at a time, with no cluster software (decision
0031). One more process makes it safe: the commit witness, a witness that also keeps the log's links. A change counts
only once the commit witness has taken it, and it takes one change per position, so two nodes that both believe they
are active can never both commit: the second is told the log moved on, steps down and rebuilds from the committed
links. A standby takes over by itself when the committed head has not moved for its hold time (30 seconds by default),
and it goes back the other way the same way. Clocks play no part in the safety, only in how soon a takeover happens.
Without the `ha` record nothing of this runs: one signer, as before.

The layout: each signer node runs on its own host with a desk next to it. The signer listens on loopback only, as
always; a desk is given its own node first and the other node second (`--signer tcp:127.0.0.1:PORT,tcp:127.0.0.1:PEER`),
the peer's loopback port reached over a link you secure (WireGuard, or an mTLS tunnel). A standby signs and serves
nothing, so a desk always reaches the active node, wherever it runs. Put the commit witness on a third machine, owned by
someone else than the signer hosts. A desk only ever follows links the commit witness took.

1. Name the commit witness and the nodes in the realm's `ha` record, in the seed records of a new realm:

   ```yaml
   ha:
     origin: keyclerk.example.org/realm            # the log's name in its checkpoints
     commit_witness: witness.example.org/commit+... # the commit witness's vkey (python -m keyclerk.witness vkey)
     nodes: [signer-a, signer-b]
   ```

   The record is signed into the log, so HA cannot be switched off by leaving a flag out, and a new commit witness is
   named the same way. For an existing realm, the security officer and a root trust owner switch it on together (see
   below) instead.
2. Stop the signer and export the seed: `python -m keyclerk.commit_witness seed --signer-state DIR --key RECORDS_KEY
   --origin ORIGIN --out SEED`. It writes every link and the records key's checkpoint of them.
3. On the witness host, with the witness stopped: `python -m keyclerk.witness reseed --state DIR --origin ORIGIN --pin
   RECORDS_PUBLIC_HEX --links SEED/links.jsonl --checkpoint SEED/checkpoint.note --key witness.key --name
   witness.example.org/commit --by NAME --reason TEXT`; for a log whose records key was rotated, add `--records-keys
   HISTORY --trustees SET` (the files you deliver to the witness anyway). Then run it with `serve --commit` (and TLS in
   front). A commit
   witness never starts from nothing: a signer refuses an empty one as an outage, and after losing the witness host you
   seed a new one the same way, from the newest log you hold.
4. Copy the stopped signer's state to the second node's host. Start each signer with `--ha-node NAME --commit-witness
   URL` (and `--ha-hold SECONDS`, at least 5). Both start as standbys; the first whose hold time passes takes over.
   `head` names the node's role, and stderr says each change of role.

An active node that cannot reach the commit witness for its hold time steps down, so desks move to its peer. While the
commit witness is away, nothing is committed and nobody takes over: the desks read on from their replicas and
proposing waits. A change whose answer was lost is answered when it is asked again, from whichever node is active.

### Switching HA on, off or to another commit witness, and break-glass
After the realm's seed, only a link the security officer and a root trust owner both confirmed puts or removes the `ha`
record; a desk's change is refused if it tries (operator 2026-11-05). Stop every signer node, then on one of them:

1. Each of the two runs `python -m keyclerk.ha nonce --signer-state DIR --key RECORDS_KEY --config FILE --by BROKER_ID`
   with the change: `--set ha.yaml` (the record as above), `--off`, or `--break-glass NODE`. It prints the statement to
   sign in with at the broker; the statement names the change and the head it is made on, so it is good for that once.
2. `python -m keyclerk.ha sign` with the same change, `--proof BROKER_ID=TOKEN_FILE` for each of the two, and the
   broker options as for a restore link. It signs the HA change link once both proofs hold.

While HA is on, give `--commit-witness URL` too. A planned change (`--set`, `--off`) is signed only on the head the
commit witness committed, so run it on the node that was active last. After `--set`, seed the commit witness from this
node's log (steps 2 and 3) and copy the state to the other nodes (step 4); after `--off`, start one signer without the
HA options.

Break-glass is for when the commit witness is lost and nothing can commit. Stop the commit witness first: the change
is refused while it still answers. The statement names the one node that signs on and its base, the head it holds;
check that this is the newest head the desks saw. That node then signs alone, without a witness, from that base, and
the change is in the log as `ha_break_glass`: treat it as an incident. A node whose history parted below the base is
refused by every desk that follows the base. HA comes back with `--set`, a commit witness seeded from that node's log.

## The reconciler's high-water mark
The reconciler keeps the newest records revision it applied in the identity broker (the `keyclerk-state` group), so a
lost state folder cannot let older signed records replay. From 0.27.0 the reconciler signs that mark with its own key:
give it `--mark-key`, a file holding an Ed25519 private key as 64 hex digits that only the reconciler reads (for
example `python -c "import os; print(os.urandom(32).hex())" > mark.key`, then restrict the file to the reconciler's
user). A mark that does not verify, or records older than the mark, refuse the revision; memberships the records never
required are still removed, and the run reports an incident. Upgrading from 0.26.x, run the reconciler once with
`--adopt-mark`: it signs the existing unsigned mark when that mark is not ahead of the records.

## Rotating the records key (0.29.0)
The records key never names its successor: the trustees do (decision record of #41). Before the first rotation:
- write the trustee set (`kc-trustees-v1`, at least two security officers and two root trust owners, nobody in both
  roles, each key on their own FIDO2 key, PIV or OpenPGP card), check it (`python -m keyclerk.trustees check SET.json`)
  and pin it in every service's configuration (`trustees: {set: FILE, since: N}`);
- write version 1 of the records-key history (`kc-records-keys-v1`: the current records key, its log origin, from link
  0) and pin it the same way (`records_keys: {history: FILE}`). Deliver both files out of band, never through the
  desk.

To change the trustee set (someone leaves, a key is lost): write version N+1, have an officer and a root trust owner
of the current set sign it (`python -m keyclerk.trustees statement kc-trustees-v1 NEXT.json`, then each signs
`NEXT.json.tosign`), and have every new key sign it too under `kc-trustees-accept-v1`. Then `python -m
keyclerk.trustees next CURRENT.json NEXT.json SIGS.json ACCEPTS.json PINNED.json` writes the new set only once it
verifies (SIGS.json and ACCEPTS.json are lists of `{trustee_id, sig}`); pin it where the old one was. A commit
witness pins one set per process: restart it with the new `--trustees`.

A rotation, with the signer stopped:
1. Take the witness's countersigned checkpoint at the signer's current size (the note the witness returns).
2. `python -m keyclerk.records_keys statement ... --new-public HEX --origin NEW_ORIGIN --note NOTE --out next`: a new
   key is a new log origin.
3. An officer and a root trust owner each sign `next.tosign` (`ssh-keygen -Y sign -n keyclerk-trustee@REALM -f KEY
   next.tosign`, or raw Ed25519 from a PIV card).
4. `python -m keyclerk.records_keys seal ... --new-key NEW.key --pinned CURRENT.json --trustees SET.json`: verified
   before it is written.
5. `python -m keyclerk.records_keys rotate ...`, then start the signer with the new key. Followers adopt the version
   from the signer; services that read no links (witnesses, backup checks) take the new history file.

After a compromise the same steps run from the last checkpoint the trustees still trust: restore the signer's state to
it first (decision 0019); followers drop what the stolen key signed after it and keep it as evidence.

## The key custodian (0.29.0)
In production the records key lives in `keyclerk-custodian` (decision 0033), a small Go process of its own user, not
in the signer: it signs a link only at the next position in its exact canonical form, and a checkpoint, note or
snapshot statement only over the tree it computed itself; it never goes below the witness's countersigned checkpoint
and never signs a position twice; everything else is refused. The signer's `--key` stays for development, tests and
the one-time migration of a signed YAML store (a custodian never signs a YAML revision).
1. Build it: `cd cmd/keyclerk-custodian && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o keyclerk-custodian .`
2. Run it as its own user. The key file is that user's only: on Unix `chmod 600` (the custodian refuses anything
   wider); on Windows a directory whose ACL grants only the custodian's account, inheritance removed.
3. A new log: `keyclerk-custodian init --state DIR --realm REALM --origin ORIGIN --key records.key`. An existing log
   (or a lost state) reaches a custodian only through the two-person ceremony: export the links with the signer stopped
   (`python -m keyclerk.commit_witness seed ... --out SEED`), write a `kc-custodian-recovery-v1` statement
   `{format, realm, origin, size, root, head, at}` in canonical JSON, have an officer and a root trust owner of the
   pinned set sign it (`python -m keyclerk.trustees statement kc-custodian-recovery-v1 STMT.json`), then
   `keyclerk-custodian recover --state DIR --realm REALM --origin ORIGIN --key records.key --links SEED/links.jsonl
   --trustees SET.json --statement STMT.json --sig ID=FILE --sig ID=FILE --witness URL --witness-vkey VKEY` (a rotated
   log adds `--origins` and `--retired HEX@UNTIL` for its earlier keys). It checks every link, and never goes below a
   state the key still reads or below the witness.
4. Serve: `keyclerk-custodian serve --state DIR --realm REALM --key records.key --listen
   unix:/run/keyclerk/custodian.sock --witness URL --witness-vkey VKEY` (the commit witness, or the detection witness
   outside HA); start the signer with `--custodian` and the same address instead of `--key`. Where there is no Unix
   socket, `--listen tcp:127.0.0.1:PORT --token-file FILE` and the signer's `--custodian-token FILE`: any local user
   reaches a loopback port, so every request carries the token. At start the custodian reads the witness and refuses
   while its state is behind it, holds another tree at its size, or the witness keeps nothing of a log with links;
   `--unwitnessed` is for development only.
5. Two signer nodes run one custodian each, with the same key and the commit witness's `--witness-vkey`: a standby's
   custodian follows the links the active node committed, exactly to the witness's countersigned checkpoint. A deposed
   node whose own uncommitted tail the active node has not yet passed waits; it never signs a position twice. A
   restarted standby custodian behind the witness serves with its floor raised and follows; it signs nothing until
   it has (a single node behind the witness is a state restored from an older copy: the ceremony recovers it).
6. Moving a custodian: `export --state DIR --key FILE --out WATERMARK` on the old machine retires it (its state is
   overwritten and removed); `import --state DIR --key FILE --from WATERMARK` on the new one only raises. The watermark
   is sealed under the key.
7. Rotating the records key: the ceremony's `rotate` step takes `--custodian ADDR` (and `--custodian-token`) instead of
   `--key`; then, with the custodian stopped, `keyclerk-custodian rotate --key OLD.key --next NEW.key --origin
   NEW_ORIGIN --from-seq N` (N the history's switch). It overwrites and removes the old key file; on journalled,
   copy-on-write or flash storage that is no erasure, so destroy its copies in backups and snapshots too.
8. With a TPM (recommended where the host has one):
   - Seal the key file to the machine's boot state: `keyclerk-custodian seal-key --key records.key --out records.sealed
     --tpm device [--pcrs 7]`, then destroy the plain file on the host and keep its backup offline. Every command then
     takes `--key records.sealed --tpm device`. A firmware or boot change (a PCR moves) stops the unseal: seal again
     from the backup. The TPM never holds the key itself (no TPM implements Ed25519).
   - Bind the state to a TPM counter: once per machine `keyclerk-custodian tpm-init --key ... --tpm device
     --tpm-counter 0x01810C10`, then add `--tpm device --tpm-counter 0x01810C10` to `serve`, `recover` and `import`.
     The counter is raised once per `--counter-epoch` (default an hour, about 8,800 writes a year; TPM counters wear
     out after roughly 100,000) and at every recovery and import. A state copied back from an older backup or disk
     image is then refused at start even when the witness cannot be read; the two-person ceremony recovers it. After a
     rotation, define a new counter for the new key the same way.
9. A key in an HSM (YubiHSM 2 or another token with `CKM_EDDSA`) needs the separate PKCS#11 build, which links
   dynamically: `CGO_ENABLED=1 go build -tags pkcs11 -o keyclerk-custodian-pkcs11 .` Every command takes `--pkcs11
   CONFIG.json`, `{"module": "/usr/lib/.../pkcs11.so", "token": "LABEL", "key": "LABEL", "pin_file": "FILE"}` (the PIN
   file is the custodian's user's only), instead of `--key`. At start the custodian checks that the token signs
   Ed25519 under the key's public half, and every signature is checked before it leaves. `rotate` refuses: a token's
   key is rotated by the token's own ceremony, then recovered onto.
10. After a recovery the signer records it in the log once, as its own record `custodian_recoveries` (the statement's
   sha256, its size, who signed it): at start, or on two nodes when a node becomes active.

## Rolling the bundle key over (0.29.0)
Edges move to a new bundle key only on a statement their own officer co-signed (`kc-edge-key-rollover-v2`, #41 F6).
With the signer stopped:
1. `python -m keyclerk.signer rollover begin --key RECORDS_KEY --state DIR --config FILE --out statements.json`
   writes one statement per live edge, signed by the current bundle key. Two signer nodes share one bundle key: make
   the next key once (`python -m keyclerk.init bundle-key --out NEXT`) and begin on every node with `--next NEXT`.
2. Each edge's officer co-signs their edge's statement (`python -m keyclerk.edge_cli cosign`); collect them all.
3. `python -m keyclerk.signer rollover finish --key RECORDS_KEY --state DIR --config FILE --statements cosigned.json`.
   It refuses unless every live edge's statement carries its officer's signature. On two nodes, finish the standby
   first, then the active.
4. Start the signer. Each edge fetches its own statement (`GET /api/v1/edge-key?edge=ID`) and pins the new key. Once
   every edge has moved, destroy `bundle-retired-N.key` and the NEXT file.

## Privileged roles granted in the broker by hand
KeyClerk grants access through the groups it manages, never through a role mapping. A privileged role mapped to a user
or a group directly, in the admin console or through the admin API, went around it. The reconciler reads the realm's
admin events at each run and reports every such grant: every `realm-management` role, and the roles you name in
`reconcile.privileged_roles` (`realm:NAME` for a realm role, `CLIENT_ID:NAME` for a client role). Each finding names
the roles, the user or group, and who made it (user, client, address). The desk notes each one once in its signed
activity log, so it shows in the broker view for the security officer and reaches the SIEM. It is report-only:
KeyClerk removes nothing it did not create.

For this, turn admin events on in the realm (Realm settings, Events, Admin events), with "Include representation" so the
finding names exactly the roles granted (without it, the reconciler reads what the user or group holds now), and give
the reconciler's reader client `view-events`. A run that cannot read the events says so in `console_grants_unread`.

## Admin accounts for privileged groups
On a privileged top group, init writes each first administrator's anchor with the persona purpose `admin`, so the
root can act on the group and add people to it from the start. The better practice, and the point of the persona
rule, is a separate admin account per person: their daily account (mail, the web) never holds privileged rights. When
those accounts exist at the identity provider, give each person both anchors, the daily one with purpose `daily` and
the admin one with purpose `admin`, and sign in with the admin account for privileged work:

```yaml
- {person: root-holder, kind: tenant, anchors: ["idp:7c1f-root", "idp:7c1f-root-admin"],
   personas: [{anchor: "idp:7c1f-root", purpose: daily}, {anchor: "idp:7c1f-root-admin", purpose: admin}]}
```

Everyone added to a privileged group later needs an admin persona the same way; without one the desk refuses the
membership and says so.

## Seeding with your own tooling

A deployment that writes its records with its own tooling needs the same minimum. As one file, the form the desk
seeds from:

```yaml
realm: example
home: example
root:
  officer: "idp:31ee-officer"
  holders:
    - {anchor: "idp:7c1f-root", appointed_by: "keyclerk-init", from: "2026-10-01T00:00:00Z"}
persons:
  - {person: root-holder, kind: tenant, anchors: ["idp:7c1f-root"]}
  - {person: security-officer, kind: tenant, anchors: ["idp:31ee-officer"]}
grants: []
revocations: []
catalogue:
  - {entitlement: admin-console, application: keyclerk, risk: privileged, owner: "idp:7c1f-root"}
groups:
  - {group_id: all, parent: null, max_risk: privileged, carries: [{entitlement: admin-console, by: "idp:7c1f-root"}]}
```

What the checks require of it:

- `realm`, `grants` and `revocations` are always present (the lists may be empty); `home` is a string.
- `root.holders` has at least one holder with `anchor`, `appointed_by` and `from` (a time with a zone); `root.officer`
  is the security officer's anchor, a different person from the root.
- Every person has `person`, `kind` (tenant, external, agent or workload) and at least one anchor. The first
  administrators are `tenant`.
- Every catalogue entry has `entitlement`, `application`, `risk` and `owner`.
- There is exactly one group with `parent: null`. A group carries only catalogue entries, each set `by` the entry's
  owner, and nothing above its fixed `max_risk`.
- An anchor is an identifier from the narrow set (letters, digits and `._:@/+-`, no spaces) and never starts with
  `uid:`.

To check records written by other tooling with the same checks as init, load them and run the engine's check:

```
python -c "from keyclerk import config, records; from keyclerk.reconcile import check_records; \
config.configure('keyclerk.yaml'); print(check_records(records.load('records')) or 'accepted')"
```

The one-file-per-record form splits from the single file with `python -m keyclerk.records split seed.yaml records/`.
