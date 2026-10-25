# 0013: The topologies KeyClerk must work in

- Status: accepted (2026-10-23, choices D1 to D6, after an adversarial review). The arrangements to account for:
  KeyClerk in another subnet than the broker; several KeyClerks and several Keycloaks; nesting, a central KeyClerk or
  midPoint handing off to decentralised children; Keycloak embedded in an application stack; realms on one instance or
  separate instances. These are the real-world arrangements KeyClerk meets, so the engine has to take each into
  account rather than assume one.
- Date: 2026-10-23

KeyClerk does not tell an organisation how to arrange its brokers. It must work correctly in the arrangements
organisations actually have, and refuse the ones that would make its guarantees false.

## The scenarios
1. **KeyClerk and the broker in different networks.** KeyClerk reaches the broker's admin and SCIM API (the
   reconciler, outbound) and its OIDC endpoints (the desk's sign-in and keys, with separate public and internal issuer
   addresses); the broker may call the desk for back-channel logout. Nothing else crosses.
2. **Many realms.** Today one KeyClerk deployment serves one realm (one records document, one desk store, one
   reconciler run per realm). An organisation with tens or hundreds of realms cannot run as many deployments by hand.
3. **Many to many.** Several KeyClerks and several brokers. Reading is free; writing is not: two writers on one realm
   fight on every reconcile and the records stop meaning anything.
4. **Nesting.** A central KeyClerk (or another IGA such as midPoint) masters some scopes and hands scopes down to
   child KeyClerks, each writing its own broker; children work disconnected within a horizon and report upward.
5. **A Keycloak embedded in an application stack.** It belongs to the application's owner, not to the organisation's
   identity team. KeyClerk may observe it, write to it under an agreement, or have it broker to the organisation's
   broker.
6. **Realms, instances and Organizations.** Organisations isolate tenants as realms on one instance, as separate
   instances, or as Keycloak Organizations inside one realm. Keycloak has no hard limit on realms; it historically
   struggled beyond some hundreds and has improved since. KeyClerk must model all three.

## Proposal
- **Targets are explicit.** A target is (broker instance, realm, optionally an Organization). Every record set names its
  target; the persona graph and the history show which target an account lives in.
- **One writer per target and fact class, enforced.** The reconciler claims a target with a marker in the realm
  (instance id, lease, fact classes); a second writer finds the marker and refuses, and the drift report names it.
- **One deployment, many targets.** One engine serves many targets with a store, policies and an audit trail per
  target, so an organisation with many realms runs one KeyClerk, not hundreds.
- **Nesting under the federation-link rules.** A parent hands a child a scope as a signed, time-limited delegation
  across the boundary: never wider than the parent's, ended by the parent, kept by the child while disconnected up to
  its horizon; the child reports evidence and changes upward. A parent may be another IGA, master per fact class.
- **Embedded brokers: observe by default.** Observe-only (read for drift, personas and evidence) is the default; writing
  needs an agreement recorded with the stack's owner; brokering to the organisation's broker is the recommended mode and
  then KeyClerk governs through claims. Every broker instance is its own control-plane trust root (0011a).
- **Networks.** A documented minimum set of flows, a startup check that reports which are reachable, and a test
  profile with KeyClerk and the broker on separate networks.

## Decision register (the choices open at the time)

| # | Decision | Options | Depends on | Notes |
|---|---|---|---|---|
| D1 | Many targets per deployment | one engine, a store and policies per target; one deployment per target (today) | | Keystone |
| D2 | One writer per target, enforced how | a marker with a lease in the realm, refused on conflict; configuration only | D1 | |
| D3 | Nesting protocol | the child pulls signed delegation bundles from the parent and pushes evidence up; the parent pushes | D1 | Reuses the federation link |
| D4 | Embedded brokers by default | observe only, writing by agreement, brokering recommended; write by default | D1 | |
| D5 | Keycloak Organizations | a target level now; later | D1 | |
| D6 | Network test | a two-network profile in the soak harness; documentation only | | |

## Adversarial review (2026-10-23)
Checked against the code, three facts shape everything:
- "One writer" today is a lock file on the reconciler's local volume: two deployments with their own state both write.
- The group marker is a fixed `keyclerk.managed` with no instance id: every KeyClerk treats every other's groups as its
  own, and the high-water mark in the `keyclerk-state` group can be forged or deleted by any realm admin.
- The approval statement binds the realm, the person and the records, but not the broker instance.

Changes before acceptance:
1. **One writer is enforced by credential, not by marker.** Each target has exactly one service account with write
   rights, and the reader checks that nobody else holds them. The marker is for detection: claimed atomically (a uniquely
   named group, refused as a duplicate), signed with the target's records key, carrying the instance id, an epoch, the
   fact classes and a schema version, re-read before every write; a missing or foreign marker freezes writing and alerts,
   never a quiet re-claim. Groups carry `keyclerk.managed=<instance id>` and a KeyClerk never touches another's.
2. **A per-target trust boundary.** Signing key, root, security officer, approval issuer and keys, and desk scope per
   target; the target id (instance, realm, organization) inside the signed records and the approval statement; no
   global viewer by default; one worker per target with its own budget; no cross-target person view unless a pair opts in.
3. **Nesting guards.** A ceiling on the child, signed by its own officer, so a compromised parent cannot widen it; a
   serial floor so an old bundle never replays; a horizon per class (privileged 1 hour, elevated 24 hours, low 7 days)
   after which privileged memberships expire at the broker; refusal of loops (the issuer path) and a depth cap of 3; the
   parent checks the child's broker, not only its reports; midPoint as a parent through a signing adapter.
4. **Embedded brokers.** Observe-only reads with view-users, query-groups and view-events, never view-clients or
   view-realm; writing only under a signed, expiring agreement with a pinned hash of the identity-provider and mapper
   configuration; trust-email and linking by email refused.
5. **The missing scenarios get refusal rules and soak tests:** groups federated from AD or LDAP are never mastered by
   KeyClerk; a broker restored from backup (a lower high-water mark) freezes writes; a realm cloned from production to
   test does not match the signed marker and is not written; two KeyClerk versions on one target are refused by schema
   version; exactly one accepted issuer per target (the internal URL is transport only); back-channel logout on its own
   listener with replay protection; Organizations observed and drift-reported now, written later.

## Decided (2026-10-23, after the adversarial review)
| # | Decision | Outcome |
|---|---|---|
| D1 | Many targets per deployment | one engine, a cell per target: own store, signing key, root, security officer, approval issuer, worker and secrets; the target id in the signed records and the approval statement; no global viewer and no cross-target person view by default |
| D2 | One writer per target | enforced by credential (one write-capable service account per target, checked by the reader) plus a signed marker claimed atomically and re-read before every write; a missing or foreign marker freezes writing and alerts; groups carry `keyclerk.managed=<instance id>` |
| D3 | Nesting | the child pulls signed, serial-numbered, time-limited bundles; serial floor; a child ceiling signed by its own officer; horizons per class with dead-man expiry; loop refusal, depth 3; the parent verifies the child's broker; evidence pushed up, signed; midPoint through a signing adapter |
| D4 | Embedded brokers | observe by default (users, groups, events; never client secrets or realm configuration); write only under a signed, expiring agreement pinning the identity-provider and mapper hash; brokering recommended with pinned mappers, trust-email off, never linking by email |
| D5 | Organizations | observe and report drift now; writing after D1 and D2 are built |
| D6 | Testing | a two-network soak profile with tests for issuer confusion, back-channel logout replay, a broker restored from backup, a cloned realm and version skew |

Known gaps in the released engine until D1 and D2 are built: the writer lock is local, the group marker carries no
instance id, and the approval statement does not bind the broker instance.
