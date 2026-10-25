# 0027. Site relays tighten, a dead edge is replaced provisionally, and KeyClerk supplies the fleet's access facts

- Status: accepted (2026-10-25), not built. The relay formats and the provisional statement come with the high
  availability profile (roadmap step 7); full site cores in 0.31.0.
- Context: an edge implementation is building a tiered fleet. One software runs at every level, recursively, at most
  three levels below the parent, each level narrower than the one above. A site gets a relay by default: the fleet view
  for its subtree, an event store that forwards upward, a cache of the last signed bundles, and the witness. Only sites
  marked as long-isolated get a full core (broker and KeyClerk). While its parent is down, a relay may only tighten
  for its subtree, and it may pass on what the parent already signed. One move widens instead: a dead edge on site is
  replaced, using a physical key per site. KeyClerk has to say how an edge checks a relay's tightening, how a
  replacement is enrolled and confirmed, how a site core is bounded, and which fleet facts are KeyClerk's.

## Decision
1. **A relay tightens with a key the officer certified.** The edge's officer signs a relay certificate
   (`kc-edge-relay-v1`, multi-signed like `kc-edge-officer-v2`) with their hardware key. It names the relay's key, the
   edges of its subtree, an expiry, and the operations it may sign: revoke a lease, end a lease earlier, cut sessions,
   suspend an edge, roll back to an earlier release that the release key signed, and hold at the current release
   (which halts a rollout without rolling back). The relay signs tightenings (`kc-edge-tighten-v1`) with that key.
   - **Who certifies.** The officer signs every relay certificate directly: no relay certifies another. The subtree is
     a list of edge ids, never a pattern, and expiries are short.
   - **What the edge checks.** The chain from its pinned officer key, through the certificate, to the tightening.
     It applies only operations that narrow its current state, and refuses one that would widen it.
   - **Ordering and replay.** Each tightening names the parent bundle serial it applies against and carries a relay
     counter that only rises; the edge refuses a counter at or below the last it applied. Any parent bundle with a
     newer serial supersedes it, and it lapses when the certificate expires, in the edge's trusted time (its newest
     signed time). A relay can therefore neither future-date a tightening past later parent bundles nor replay an old
     one.
   - **Suspend, not end.** A relay suspends an edge; a parent bundle lifts the suspension. Only the officer's ended
     notice ends an edge, so a stolen relay key can never force a re-enrolment.
   - **The release floor.** The edge keeps a minimum release with its floors and refuses anything older, unless a
     downgrade statement signed by the release key names that move. A relay's rollback goes no lower than the floor.
     A hold cannot keep an edge below the floor, expires with the certificate, and raises an alarm.
   - **Withholding is bounded, not prevented.** An edge detects a relay that serves a bundle older than one it already
     holds (its serial floor) and a parent that has gone quiet (the bundle's horizon). It cannot see a newer parent
     bundle a relay hides. A withheld revocation therefore lasts at most until the horizon of its class ends (one hour
     for privileged access), when the leases it would have narrowed stop being live anyway.
   - **The residual.** A stolen relay key cannot widen anything. It can deny service to its subtree, by suspending
     edges and revoking leases, until its certificate expires or a parent bundle supersedes it.
2. **A dead edge is replaced provisionally, with no new authority.** A bundle is bound to the edge's id and signed by
   the bundle key, so a replacement installed with the same pins runs on the relay's cached bundle for that id. By
   construction, that gives it the dead edge's slot, ceiling and targets, never wider. On site, the site's physical
   key and the new node sign an officer statement with the purpose `provisional`. It names the dead edge's id and the
   new node's enrolment key. There is one physical key per site, enrolled at the desk like an officer key and pinned
   in each of the site's edges' enrolment beside the rotation anchor pinned from 0.30.0. The edge implementation's
   break-glass promotion of a node uses the same key and statement.
   - **When.** The relay accepts a replacement only after the dead edge has been silent for a period the edge's policy
     states, and at most one provisional replacement per edge id.
   - **The original comes back.** If the original id reports again, the relay freezes both until the officer decides;
     the statement format fixes this precedence.
   - **The site key** needs a PIN or presence for each use, and each use carries its own label (`provisional` for a
     replacement, `promotion` for the edge implementation's node promotion), so a statement signed for one can never
     serve as the other.
   - **The relay** serves the cached bundle only to a key with such a statement. It logs this and shows it on its
     status page.
   - **It ends by itself** with the cached bundle's horizon: a provisional key never receives a refreshed bundle.
   - **On reconnect,** the officer confirms the replacement with a `rotation` statement, or ends it with the ended
     notice, which then applies at the next pull. Until then, the desk refuses the new key.
3. **A full site core is a nested KeyClerk (decision 0013 D3).** Its parent bounds it:
   - it pulls signed, serial-numbered, time-limited bundles from the parent;
   - its own officer signs its ceiling, so a compromised parent cannot widen it;
   - each class has a horizon with dead-man expiry;
   - loops are refused, and nesting stops at depth 3;
   - the parent verifies the child's broker, and the child pushes its evidence upward, signed.

   It needs many targets per deployment and one writer per target (0013 D1 and D2) first. All three are built
   together in 0.31.0, after the engine is public. Until then, sites get relays, which tighten but never grant.
4. **The fleet view is the edge implementation's; KeyClerk supplies its access and evidence facts to it.** No clerk
   can be assumed present (KeyClerk or another identity governance product is one of several possible), so the edge
   implementation keeps its own fleet service, in its core and in each relay: last pull, applied serial, version,
   drift, attested profile, silence, and rollouts through its own signed release manifests.
   - **What KeyClerk supplies when present:** the leases and serials it issued, against what the edge applied (the
     omission cross-check), the relay tightenings in force, provisional replacements, and evidence.
   - **KeyClerk's own alarm:** `edge_silent` stays, for the edges KeyClerk issues bundles to.
   - **Not KeyClerk's and not the relay's:** link crypto, hardware health and resource use stay in the organisation's
     OpenTelemetry. The relay carries evidence and governance events, never device telemetry.

## Consequences
- The edge protocol gains two formats (`kc-edge-relay-v1`, `kc-edge-tighten-v1`) and two statement purposes
  (`provisional`, `promotion`). Each has conformance vectors, and the tighten-only rule is a verifier check.
- An isolated site keeps narrowing access, and can replace hardware, without any key that can widen access.
- A long-isolated site that must also grant waits for 0.31.0.

## Amendments
- 2026-10-25, the same day: point 4 reshaped with the edge implementation (the fleet view is its own; KeyClerk supplies
  its facts), point 1 gains "hold at the current release", point 2 names the site key and its pin.
- 2026-10-25, the edge implementation's adversarial review: ordering and replay of tightenings (parent serial, rising counter,
  lapse in trusted time); a relay suspends, never ends, an edge; the release floor bounds rollback and hold; the officer
  certifies every relay directly, subtrees as lists, short expiries; withholding bounded by the horizon; a provisional
  replacement only after a silence period, one per edge id, both frozen if the original returns; the site key needs a
  PIN or presence and labels each use.
