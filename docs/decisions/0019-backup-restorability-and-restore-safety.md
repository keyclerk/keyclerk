# 0019. Off-site backup, restorability and restore safety

- Status: accepted (2026-10-24, choices H7 and H8), not built. Since 2026-10-24: built on decision 0022's signed change log (backup = the log plus signed snapshots; restore replays and verifies the chain), 0.27.0.
- Context: what cannot be rebuilt is the records store (signed revisions and the log), the event log, and the desk's
  state per edge (serials and floors, ceilings, incidents, evidence acknowledgements); the broker state is re-read by
  the next reconcile. The bundle key and the desk's unlock key sit beside the store: a copy of the volume carries keys
  that sign bundles. A design rule: no paper recovery. Recovery material lives in a password manager and on a second
  custodian's device, because a printed sheet or a show-once code is lost, copied or photographed without anyone
  knowing.

## Decision
1. **A snapshot only KeyClerk can make (H7).** `keyclerk backup` takes a consistent snapshot at a revision (store,
   event log, edge state), verifies it (chain, signatures, the full check), leaves out every key, and encrypts it to
   recovery keys held by two custodians. The deployment's backup tool ships it to off-site object storage with object
   lock. Keys are escrowed apart (a password manager, a second custodian), never in a data backup. The signer's state
   is in scope too (its replica, its log mark and its audit.jsonl), and a restore verifies the audit chain.
2. **Hygiene.** A schedule and a retention target in policy; custodian recovery keys rotated while older
   snapshots stay readable; pruning only by the shipper; a check that the escrowed keys are still there.
3. **State.** A signed manifest per snapshot (revision, hash, size, time, verification result, where and
   when it was shipped), so the newest good off-site copy is a known fact and a metric (0018) that alerts when it ages.
4. **Restorability.** A scheduled restore drill: fetch the newest off-site copy into a scratch desk, decrypt
   with a custodian test key, verify chain and signatures, run the full check, compare the revision hash with its
   manifest. The time it takes is the measured recovery time; a failure is an incident.
5. **Restore safety (H8).** A restored desk starts in restore mode: no writes, not ready (0018). It takes the
   high-water mark from the witness's countersigned heads, the heads edges echoed and each edge's last applied serial,
   and the manifest; records revisions and each edge's bundle serial resume above it; it runs the full check, then
   serves. Revisions lost since the snapshot are an incident, with what the witness proves of them; people propose them
   again, nothing rebuilds them automatically. Without a known high-water mark, two people confirm one by signature.
   The witness (governance feature G10, decision 0020) comes before or with backup.

## Consequences
A disk loss costs at most the snapshot interval, never a forked history or dark edges, and every restore is proven by
drill before it is needed.
