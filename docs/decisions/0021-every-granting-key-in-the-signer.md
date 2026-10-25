# 0021. Every key that grants lives in the checking signer

- Status: accepted (choice E3 of 2026-10-23 and choice G14 of 2026-10-24), not built. Since 2026-10-24: the witness co-signs 0022's per-change checkpoints; 0.29.0.
- Context: decision 0015 moved the records key into the checking signer. The bundle key (bundles for edges) and the
  desk's unlock key (phoned unlock codes) still live in the desk, so a taken-over desk can sign a bundle with any lease
  in it, or read an unlock code for anyone (found by an adversarial review of the 0.23.0 release, 2026-10-24). A
  lease's username
  and e-mail come from files the reconciler writes beside the desk, and Warpgate matches a single sign-on login by
  e-mail only (found by the edge implementation in warpgate-core's db.rs, at upstream commit a2570d7), so a forged
  e-mail signs an attacker in as the lease holder.

## Decision
1. **The bundle key and the unlock key move into the signer.** Before it signs a bundle, the signer checks every lease
   and visit lease in it against the records it signed (the person holds it, inside its window, inside the ceiling),
   and before it computes an unlock code, it checks the approver's proof (0015) and edge.rego's limits.
2. **A sealed identity map (G14).** The reconciler seals the map of anchor, broker username and verified e-mail
   (`kc-identity-map-v1`, with its revision and time) with its own key, which the signer pins. A lease's identity
   fields are accepted only when they match the newest map. The reconciler runs as its own user, as the signer does: a
   deployment rule.
3. **Upstream next.** Warpgate matching a login by provider and subject (the broker's user id) is proposed upstream as
   a separate item, through Warpgate's own contribution process; once it is released, the e-mail leaves leases.

## Consequences
A taken-over desk can refuse, delay and log noise, but cannot widen access anywhere: not in the records, not on an
edge, not by a phoned code. A third key (the reconciler's) is added to protect.
