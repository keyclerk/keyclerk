# 0002: The core decides and keeps the lifecycle; every outside system is a plugin

- Status: accepted
- Date: 2026-10-22
- Decider: maintainer

## Context
The lifecycle of broker groups and physical access was built; devices, network groups, host access, app-local roles,
privileged sessions, data rights, non-human identities, reviews and movers were designed but provisioned nowhere.

## Decision
1. **The rule.** The core decides and keeps the lifecycle state and never calls an outside system. A plugin talks to
   one outside system through the connector contract and never decides who gets access. What is another system's own
   job stays out of KeyClerk.
2. **Core:** the carrier register (each catalogue entitlement names how it reaches its system; the plan covers every
   carrier, removals first); devices as subjects (record, owner, issued, enrolled, retired, device grants; posture and
   enrolment arrive as signals); non-human subjects (workload and agent, with an owner, a lease and the owner's leaver
   handled); review campaigns; movers recomputed from the source; the escort, two-person and delegation decisions.
3. **Plugins**, off by default: the Keycloak broker (on by default, the reference plugin; the core never assumes it),
   overlay network groups and peers, SSH certificates per activation, Linux groups, privileged-session gateways,
   generic SCIM and per-app adapters, relationship tuples, database roles through a secrets engine, key-access grants,
   workload identity issuance, PACS and OSDP, posture sources.
4. **Not KeyClerk:** the content of network and firewall policy (it keys on the groups KeyClerk fills), posture
   measurement, secret and certificate issuance mechanics, a platform's inventory of static credentials, Windows GPO.

## Consequences
The core grows by the carrier register and multi-carrier plan, device and non-human subjects, review campaigns and
mover recompute. The access-path analysis checks that a grant's route is provisioned end to end: a checkpoint whose
requirement no carrier delivers is a broken route.
