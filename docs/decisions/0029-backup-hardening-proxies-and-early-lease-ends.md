# 0029. Backup hardening, the client address behind a proxy, and a lease that ends early

- Status: accepted (2026-11-03, maintainer, decision series N1 to N10). Builds on 0019 (backup) and 0028 (erasure
  and retention). For 0.27.0. Built 2026-11-03: points 1, 2, 4, 5 and 6 (`keyclerk/backup.py`, `keyclerk/restore.py`).
  Point 6 also puts a restored signer in restore mode until recover-log or the restore link, and gives a desk on the
  change log its way out of restore mode (`restore leave`). Built 2026-11-04: points 3 and 7 (`keyclerk/config.py`,
  `keyclerk/api.py`); point 7 reads one header, chosen in `api.forwarded_header`, so a client cannot add the other.
  Point 8's wire part as well (edge protocol 1.4, `lease_ended_early`); the adapters' checks at start are each edge's
  own. Point 9 ran 2026-11-04 on one lab box (ccx23): E5 reproduced and fixed, and the drill restored the generated
  organisation in 40 s (docs/testing/realistic-load.md).
- Context: building backup (issue 26) and reading the open review rows and upstream threads turned up issues in the
  backup just built, a residual of the 2026-10-26 review (C3), and a bastion behaviour that ends a lease's access
  early (Warpgate #2785: with a roles claim and no role mappings, a sign-in revokes every role SSO did not grant).

## Decision
1. **A backup streams (N1).** Take and restore go through temporary files, never the whole store in memory: the
   change log is built for tens of thousands of people.
2. **Recipients are policy (N2).** A backup is encrypted only to the recipients in `backup.recipients`; `take` refuses
   any other, so a changed schedule cannot add a recipient that receives every record.
3. **View logs stay in backups, retention bounded (N3).** The record of looks (0009) survives a restore. The
   configuration is refused when `backup.retention_days` exceeds `store.view_log_keep_days`, so a backup never keeps
   a look longer than the desk does.
4. **Only the current replica (N4).** Replicas left by earlier resyncs are not backed up.
5. **Shipping is a fact (N9, 0019 point 3).** A signed record beside each manifest says where and when it was
   shipped.
6. **Backups forget (N10, 0028 point 6).** An erasure journal (what was erased and when, by internal id, no personal
   data) is kept apart from the backups. A restore applies the newest journal before the desk serves and is refused
   without one. It starts with erased visits; erased anchors join it with 0028 point 3.
7. **The client address behind a proxy (N5, C3).** `api.trusted_proxies` lists proxy networks, empty by default. Only
   from a listed proxy does the desk read `Forwarded` or `X-Forwarded-For` (one, chosen in config), and it takes the
   rightmost address that is not a listed proxy. The public scan budget is kept per client.
8. **A lease that ends early is an incident, whatever the bastion (N6).** The edge wire gains an incident kind: a
   lease's assignment at a bastion ended before its expiry. Each bastion adapter lists the bastion settings known to
   drop a lease's assignment and flags them at start (Warpgate's first: a roles claim without role mappings). The wire
   addition ships with the 0.27.0 edge protocol release (issue 31).
9. **One lab run (N7, N8).** One lab box, with a deadline, verifies E5 (child groups under a managed group) against a
   live Keycloak and runs the timed restore drill on a generated organisation.

## Considered
- View logs: leave them out of backups (less personal data off-site, but a restore loses the record of looks), or a
  separate archive with its own retention (more moving parts).
- The client address: leave it to the proxy (no header parsing in the desk, but the desk's own budget stays shared),
  or a budget per scanned code (does not stop one client cycling codes).
- A lease ending early: a configuration check alone, or a note in the install guide only.

## Consequences
A backup is safe to run at the sizes the change log targets, cannot be widened to another reader by changing a
command line, and never brings back what was erased or keeps a look past its retention. A deployment behind a proxy
keeps the scan budget per client. An edge sees a bastion take away a lease's access early, on any bastion.
