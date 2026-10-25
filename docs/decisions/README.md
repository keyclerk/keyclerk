# Decision records

KeyClerk's own design decisions: why the engine is built the way it is. A deployment records its decisions about
using KeyClerk (adoption, configuration, which plugins it enables) in its own repository.

| # | Decision |
|---|---|
| [0001](0001-configuration-as-code.md) | The engine holds no rules and names no deployment |
| [0002](0002-core-and-plugins.md) | The core decides and keeps the lifecycle; every outside system is a plugin |
| [0003](0003-keycloak-integration.md) | Keycloak through SCIM as measured on 26.8.1 |
| [0004](0004-scope-1-0.md) | 1.0 is the broker lifecycle, with its own requests, approvals and campaigns |
| [0005](0005-desk-and-api-contract.md) | The desk: one API contract for every front end; changes become signed record revisions |
| [0006](0006-approvals-as-signatures.md) | Approvals are the approver's own signature, made by the broker after a fresh sign-in |
| [0007](0007-what-the-broker-offers.md) | Use what the broker already offers: back-channel logout, events, step-up, DPoP, phone approvals |
| [0008](0008-second-key-standing.md) | A second key needs standing, decided by one policy compiled into the engine |
| [0009](0009-visits-evidence-and-observability.md) | Visits with vehicles, passengers and kit; checked evidence; access over time |
| [0010](0010-person-first-visits-and-access-in-hours.md) | Person-first visits, access in hours, and how settings are shaped |
| [0011](0011-personas-workloads-and-agents.md) | Personas, workloads and agents |
| [0011a](0011a-admin-personas-by-plane.md) | Admin personas by plane (amends 0011) |
| [0012](0012-persona-history.md) | A persona's history, and the history of the identity providers behind it |
| [0013](0013-topologies.md) | The topologies KeyClerk must work in |
| [0014](0014-edges-bundles-person-keys-relay.md) | Edges - signed bundles, ceilings, visit leases, person keys, the relay, escrow and evidence |
| [0015](0015-checking-signer-and-proposer-proofs.md) | A checking signer holds the records key, and a high-risk change carries its proposer's own signature |
| [0016](0016-edge-tpm-attestation.md) | An assured edge proves its TPM, its attestation key and its boot state |
| [0017](0017-access-timeline-and-incremental-checks.md) | An access timeline per revision, and checks scoped to what a change reaches (accepted in part: scoped checks deferred) |
| [0018](0018-operations-interfaces.md) | Health, metrics, audit export to a SIEM, SOAR, identity visibility and Shared Signals |
| [0019](0019-backup-restorability-and-restore-safety.md) | Off-site backup with hygiene, manifests and restore drills; a restore never signs a revision twice |
| [0020](0020-governance-features.md) | Reviews, dormancy, impact diffs, SoD exceptions, holder bounds, outliers, orphans, agents, witness, leaver proof |
| [0021](0021-every-granting-key-in-the-signer.md) | The bundle and unlock keys in the checking signer, and a sealed identity map |
| [0022](0022-signed-change-log-and-sqlite-store.md) | The signed change log as the source of truth, on SQLite; personal data outside the log |
| [0023](0023-session-constraints-in-the-lease.md) | Session constraints in the lease, enforced by edges that declare what their gateway can do |
| [0024](0024-external-sign-in-bindings.md) | External people sign in at their own provider only through a governed binding |
| [0025](0025-governed-roles-in-the-edge-bundle.md) | The bundle names the edge roles KeyClerk governs |
| [0026](0026-the-bundle-long-poll.md) | An edge may wait for its next bundle |
| [0027](0027-relays-provisional-replacement-and-the-fleet-view.md) | Site relays tighten, a dead edge is replaced provisionally, and KeyClerk supplies the fleet's access facts |
| [0028](0028-personal-data-erasure-and-retention.md) | Personal data in the log: an internal anchor, erasure that reaches every copy, and retention the deployer sets |
