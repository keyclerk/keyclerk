# Roadmap

The order of work. Which issues belong to a version is its GitHub milestone; this page gives the order and the
direction. It changes in the pull request that adds or moves an issue. Versions after the next one may move.

## Done
- 0.28.0: high availability for edges and the core signer: an edge's two nodes, each on record with how it became
  active; a core standby that takes over by itself, refereed by a witness that accepts one history only; an edge's
  trusted time; edge protocol 1.5.
- 0.27.0: backup and restore with a measured drill, restore safety, signed snapshots, a witness for the change log,
  SIEM and SOAR interfaces, approvals that name their sign-in level, edge protocol 1.4 (#26 to #31).
- 0.26.x: the desk on the signed change log, hardening after a review, the first release on PyPI.
- 0.25.0: the signed change log on SQLite as the source of truth (decision 0022).
- 0.24.0: flattened groups per revision, a timeline per person, health, readiness and Prometheus metrics.
- 0.23.0 and earlier: one signing mode, policy modules by hash, the checking signer, offline edges.
- Edge protocol 1.0 to 1.5 (github.com/keyclerk/edge-protocol).

## Next: 0.29.0, trust
1. #38 Every key that grants lives in the checking signer: bundles and every object an edge verifies are built
   there, from the records it signed; the unlock key moves in too.
2. #39 A sealed identity map names each lease's bastion account.
3. #40 A key custodian under the checking signer, refusing anything that would fork or rewrite the change log.
4. #41 The records key rotated and recovered after a compromise.
5. #42 Minimal access reviews, with a grace period for people who move.
6. #43 Groundwork for EU digital identity wallets.
7. #44 A validity window on the site key's promotion statement (with keyclerk/edge-protocol#18, edge protocol 1.6).
8. #37 The desk and the management listener listen on IPv6.

## Then: 0.30.0, people and wallets
1. #45 People, engagements and sponsors, identified or pseudonymous.
2. #46 Receiving credentials from EU digital identity wallets, remotely and at the desk.
3. #47 A proximity reader for wallets at the desk.

## Later
- 0.31.0: session constraints in the lease and external sign-in bindings; holder bounds and separation-of-duty
  exceptions; many targets, nested KeyClerks, and any IGA (such as midPoint) as a parent above KeyClerk.
- 0.32.0: governance analytics (impact diffs, dormancy, orphans, outliers, leaver proof).
- 0.33.0: an identity visibility API, Shared Signals, and an LDAP directory connector.
- A signed, minimal release image rebuilt on every base update.
