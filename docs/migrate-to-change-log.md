# Moving a deployment to the signed change log

From KeyClerk 0.26.0 a desk can keep its records in the signed change log on SQLite (decision 0022) instead of the
signed YAML store. This page is the order of work for a running deployment, what to check at each step, how to go
back, and what to delete afterwards. Read decision 0028 first: on the change log people are named by internal
anchors, and the identity provider's ids live only in erasable mapping tables.

What changes for people: nothing they see, apart from the desk's history, which starts again with one line, "migrated
from signed YAML revision n". The YAML-era history is kept aside as a file (step 9 says when it goes).

## Before you start
- KeyClerk 0.26.0 or later everywhere: the desk, the checking signer, the reconciler. Edges on edge protocol 1.3 get
  a lease's e-mail by request; an edge on 1.2 keeps working, without the address.
- A desk that already signs through the checking signer (`--signer`, decision 0015). A desk that holds the records
  key itself moves to the signer first; that is its own change.
- The signer's last signed revision passes this engine's checks. The migration refuses otherwise and lists the fixes;
  make each with an ordinary change on the YAML store and start again.
- A maintenance window: the desk and the reconciler are stopped from step 2 to step 6. Edges keep working on their
  bundles for their horizons.
- Backups, taken in step 3, of the desk's store folder and the signer's state folder, restorable as a pair.

## The steps
1. **Settle the pending changes** where you can: approve or withdraw them. Those left are carried over (their people
   re-keyed) and can still be approved after the move, but fewer is simpler.
2. **Stop the reconciler, then the desk.** The migration takes the desk store's lock and refuses while a desk holds it.
   Leave the signer running.
3. **Back up** the desk's store folder and the signer's state folder, together. This pair is your way back (below).
4. **Migrate**, on the desk's host, into the desk's own folder:

   ```
   python -m keyclerk.store.migrate STORE STORE/log.db --signer unix:/run/keyclerk/signer.sock --config keyclerk.yaml
   ```

   The signer migrates its own last signed revision (never one the desk hands it): it re-keys every person to an
   internal anchor, mints the mapping rows and an accounts record per account, and signs the genesis. The command then
   builds the desk's replica from the signer's links, proves the migration, re-keys the pending changes
   (`pending.json`; the YAML-era file is kept as `pending-yaml.json`), moves the YAML-era activity log aside
   (`log-yaml.jsonl`) and writes the first line of the new history. It prints what it did:
   `revision n, links k, records r, migration proven, pending p, ...`.

   If it stops with a refusal, nothing was signed or nothing was finished: read the reason, restore the backups of
   step 3 if it says the desk's files were touched, and run it again.
5. **Switch the desk to the change log**: in the configuration, `store: {kind: sqlite}`. Start the desk with the same
   `--store` folder and `--signer` as before. Check:
   - the desk starts and its readiness is green;
   - the desk's history shows the one "migrated" line;
   - the desk's head is the signer's head (`/readyz` and the signer's `head` agree on size and head).
6. **Switch the reconciler to the change log**: replace `--records FILE --signing-key KEY` with

   ```
   --log-replica STATE/log.db --signer unix:/run/keyclerk/signer-reconciler.sock --records-key records.pub
   ```

   The reconciler talks to the signer's own listener for it: start the signer with
   `--reconciler-listen unix:/run/keyclerk/signer-reconciler.sock` (a socket only the reconciler's user can open), or a
   TCP port with its own `--reconciler-token` file. The desk's socket refuses subject links (decision 0028, 2026-10-26).

   `records.pub` is the records public key in hex, the same key the YAML store's signature was checked with; pin it from
   your own copy, never from the signer. Run it once without `--apply` and read the plan: it must be empty, or hold
   only what was due anyway. Then start it as before.
7. **Watch phase 2.** On each run the reconciler links the accounts it sees through their anchor attribute to their
   broker subject (decision 0028); from then on those people sign in, approve and are reconciled by subject only. The
   run log's findings name any account it could not link: an anchor attribute on two accounts, or moved to another
   account, is an incident for the security officer.
8. **Watch for a week**: `keyclerk_log_breaks` (breaks in the desk's activity log, and a desk that could not follow
   the signer), the signer's
   background full check, and the reconciler's refusals. A replica that falls behind or breaks resyncs from the signer
   by itself; one that cannot is an alarm with its reason.
9. **Purge the YAML era** once you will not go back (step back below): these files name people by the identity
   provider's id, and decision 0028 keeps those ids only in the erasable mapping.
   - in the desk's store folder: `records.yaml`, `records.yaml.sig`, `revisions/`, `visits/` (now in the replica),
     `pending-yaml.json`, `log-yaml.jsonl`;
   - in the reconciler's state folder: the last applied document (`last-applied.json`) is rewritten by its first run
     on the change log; delete older copies;
   - in the signer's state folder: `last.yaml` and `last.json`, the YAML-era revision it migrated from;
   - their copies in backups and in any repository that held the records as code, including its history.
   Your data protection officer decides how long the backups of step 3 are kept.

## Going back
- **Before the first change on the change log**: stop the desk and the reconciler, restore the pair of backups from
  step 3, set `store: {kind: yaml}` (or remove the section), start the YAML desk and the reconciler with `--records`.
  Edges are unaffected.
- **After changes on the change log**: there is no automatic way back. `python -m keyclerk.store.migrate --export DB
  --pinned KEY --realm REALM --config FILE` writes the replica's records as YAML, but with internal anchors; turning
  them back into identity provider ids and signing a new YAML revision is a manual recovery, done with the security
  officer. Decide before step 5 how long you keep the way back open.

## What can go wrong, and what it says
| Where | What you see | What to do |
|---|---|---|
| step 4 | "the revision to migrate does not pass the engine's checks" with fixes | fix each on the YAML store, migrate again |
| step 4 | "a desk process holds STORE" | stop the desk and anything else using the folder |
| step 4 | "STORE/log.db exists" | a failed attempt: restore the step 3 backups, then migrate again |
| step 4 | "the desk's published records are not the revision the signer migrated" | the desk and the signer disagree: restore the desk's `records.yaml` from its revisions, or ask the security officer |
| step 5 | the desk refuses `store.kind sqlite` | the engine is older than 0.26.0 |
| step 6 | "mapping rows do not match the log's accounts records" | the mapping was changed outside the signer: resync the reconciler's replica (delete it; it is rebuilt) and tell the security officer |
| step 6 | "the records want accounts the mapping does not name" | an account was erased while still wanted: the reconciler writes nothing for it; fix the records |
| step 7 | "linked to another subject" in the findings | an incident: an anchor attribute was moved between accounts |
