# 0025. The bundle names the edge roles KeyClerk governs

- Status: accepted (2026-10-25), built in 0.25.0. Edge protocol 1.1 (an optional bundle member; edge protocol 1.0
  edges ignore it).
- Context: an edge acts on the leases in its bundle and leaves accounts it does not manage alone by design: a
  bastion's own administrator, a site's break-glass account. That leaves a gap. An unmanaged account given a role that
  reaches a controller behind the edge, outside any lease, is not reported, because the edge cannot tell a role
  KeyClerk governs from one it does not. The bundle carries leases, never the set of roles they are drawn from. An
  edge implementation found this in its own full-stack review and asked for the set, signed. The pattern is identity
  governance reconciliation against an entitlement catalogue: a holder of a governed role without a grant for it is
  drift.

## Decision
1. **A member of the bundle, not a document beside it.** `governed_roles` sits inside `kc-edge-bundle-v3`, so it has
   the bundle's signature, its serial floor and its completeness rule: a stale or replayed bundle is already refused,
   so an old catalogue can never shrink the set. A separate document would need its own floor and its own pull for no
   gain.
2. **SCIM Group shape.** Each entry is `{displayName, externalId?}`, a subset of the SCIM 2.0 Group resource
   (RFC 7643 section 4.2), so an edge can reconcile against KeyClerk or any identity governance product that speaks
   SCIM with one reader. `displayName` is the role name as the edge's gateway knows it; `externalId`, optional, is a
   name the deployment uses for the same role elsewhere. No other member (no `members`: who holds a role comes from
   the leases, and a member list in the catalogue would be a second, conflicting source).
3. **What KeyClerk puts in it.** The roles the edge's enrolled targets map to (each target's `role`), each once, sorted.
   Enrolling or changing a target changes the set with the next bundle.
4. **Absent, empty and present mean three things.**
   - absent: no catalogue. The edge falls back to its own list of governed roles (its targets file) and never reads
     the absence as "nothing governed". Bundles from KeyClerk before 0.25.0 are all in this case;
   - present and empty, signed: KeyClerk governs no role on this edge;
   - present: these roles. An edge that also keeps its own targets file governs the union.
5. **Report, never remove.** A holder of a governed role without a live lease or visit lease for it is drift. The edge
   reports it (to its operator and to KeyClerk as evidence); it does not take the role away, because the holder may be
   an account the edge must never touch, and a catalogue error must not lock a site out.
6. **Strict shape.** A verifier refuses the whole bundle when `governed_roles` is present but is not a list of objects
   with a non-empty string `displayName`, an optional string `externalId` and nothing else, or names a role twice. Null
   is not absence: it is refused.
7. **Proven by vectors.** The conformance set's bundle verifier records present, absent, signed-empty and
   with-externalId as accepted (with the role list an edge reads), and a role named twice, an unknown member, null and
   bare names as refused. Every case's expected output carries `governed_roles` (null when absent or refused).

## Consequences
- A drift report on an edge has a signed basis: the role was governed, the holder had no lease.
- The set is per edge, so an edge learns nothing about other edges' roles.
- Edge protocol 1.0 edges keep working: the reference verifier reads only the members it knows.
- Not here: removal of drifted holders (a deployment decision, and an edge's, never the catalogue's), roles governed
  per target rather than per edge (a role on one target and not another; enrolment maps roles per target already, so
  this can follow when an edge needs it).
