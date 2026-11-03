# Roadmap

The order of work. Which issues belong to a version is its GitHub milestone; this page gives the order and the
direction. It changes in the pull request that adds or moves an issue. Versions after the next one may move.

## Done
- 0.26.x: the desk on the signed change log, hardening after a review, the first release on PyPI.
- 0.25.0: the signed change log on SQLite as the source of truth (decision 0022).
- 0.24.0: flattened groups per revision, a timeline per person, health, readiness and Prometheus metrics.
- 0.23.0 and earlier: one signing mode, policy modules by hash, the checking signer, offline edges.
- Edge protocol 1.0 to 1.3 (github.com/keyclerk/edge-protocol).

## Next: 0.27.0, backup, restore safety, SIEM and SOAR
1. #27 Restore safety: a restored desk never signs a revision number twice.
2. #26 Backup and restore: snapshot, manifest and a measured restore drill.
3. #28 Signed snapshots of the change log.
4. #31 Edge wire additions in one protocol release (with edge-protocol #10), so an edge ports once.
5. #29 SIEM: a pull API and syslog over TLS.
6. #30 SOAR: webhooks and protective proposals.

## Then
- 0.28.0: a high-availability profile, two nodes per edge, each node reporting how it became active.
- 0.29.0: every granting key in the signer, so a taken-over desk cannot sign what the records do not allow.
- 0.30.0: session constraints in the lease, and external sign-in bindings.

## Later
- 0.31.0: reviews, holder bounds and separation-of-duty exceptions; many targets and nested KeyClerks.
- 0.32.0: governance analytics (impact diffs, dormancy, orphans, outliers, leaver proof).
- 0.33.0: an identity visibility API, Shared Signals, and an LDAP directory connector.
- A signed, minimal release image rebuilt on every base update.
