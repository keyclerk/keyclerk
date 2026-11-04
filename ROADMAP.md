# Roadmap

The order of work. Which issues belong to a version is its GitHub milestone; this page gives the order and the
direction. It changes in the pull request that adds or moves an issue. Versions after the next one may move.

## Done
- 0.27.0: backup and restore with a measured drill, restore safety, signed snapshots, a witness for the change log,
  SIEM and SOAR interfaces, approvals that name their sign-in level, edge protocol 1.4 (#26 to #31).
- 0.26.x: the desk on the signed change log, hardening after a review, the first release on PyPI.
- 0.25.0: the signed change log on SQLite as the source of truth (decision 0022).
- 0.24.0: flattened groups per revision, a timeline per person, health, readiness and Prometheus metrics.
- 0.23.0 and earlier: one signing mode, policy modules by hash, the checking signer, offline edges.
- Edge protocol 1.0 to 1.4 (github.com/keyclerk/edge-protocol).

## Next: 0.28.0
- A high-availability profile for edges and the core signer: a standby becomes active only by a witness grant or a
  two-person break-glass, never on a timeout.

## Then
- 0.29.0: trust. Every granting key in the signer, the records key rotated and recoverable after a compromise, and
  access reviews by owners.
- 0.30.0: session constraints in the lease, and external sign-in bindings.

## Later
- 0.31.0: holder bounds and separation-of-duty exceptions; many targets, nested KeyClerks, and any IGA (such as
  midPoint) as a parent above KeyClerk.
- 0.32.0: governance analytics (impact diffs, dormancy, orphans, outliers, leaver proof).
- 0.33.0: an identity visibility API, Shared Signals, and an LDAP directory connector.
- A signed, minimal release image rebuilt on every base update.
