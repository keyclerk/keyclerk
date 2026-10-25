# 0006: Approvals are the approver's own signature, made by the broker after a fresh sign-in

- Status: accepted
- Date: 2026-10-22
- Decider: maintainer

## Context
A two-person rule (a second key from outside the actor's chain, a manager's key, the security officer's key, two
people to lift a suspension) is only as strong as the place approvals are written. Since decision 0005 the desk writes
them into records it signs with its one key: a review found that whoever held that key could write any approval.
Suspensions were also outside the history guard, so a two-person lift rested on that one key. Options considered:

- separate keys per person (passkeys, WebAuthn): device-bound and the strongest, but every key must be enrolled and the
  enrolment itself anchored outside the desk, a public key infrastructure of its own;
- the broker as the second, independent signer: people already sign in there, it signs ID tokens with keys the desk
  does not hold, and OIDC binds a nonce of our choosing into the token;
- leave it with the desk and accept the single key.

## Decision
1. **An approval carries a proof the broker signs.** The approver signs in again (prompt=login, max_age=0) with the
   OIDC nonce set to the statement of the change: base64url(sha256) of the realm, the approver's anchor and the
   records approved, without their approval lists, so every approver of one change signs the same records. The ID
   token is the proof; it is kept in the records (approval_proofs, which only grow).
2. **The reconciler verifies every approval key** (memberships, delegations, grants, suspension lifts) against the
   broker's published keys: issuer, an allowed client, the nonce, the approver's anchor, and a sign-in at most
   approvals.max_age_seconds old when the token was issued. One approval without a valid proof refuses the revision.
   Keys the broker published once are archived, so proofs outlive key rotation.
3. **Approvals made before proofs** (records reviewed elsewhere, such as in git) are accepted only when the deployment
   pins them, record and approver, in approvals.accepted_without_proof. A new approval cannot be backdated into that
   list without changing the deployment's configuration.
4. **The desk checks a proof before it records an approval** and gives other front ends the nonce
   (GET /changes/{id}/statement); its own front end sends the approver through the broker and back.
5. **Suspensions are history-guarded:** never dropped, never changed, lifted once.
6. Proofs are off unless a deployment sets approvals.proofs to required.

## Consequences
- Holding the desk's signing key, or write access to its store, no longer lets anyone pass a change that needs a
  second key: the broker's key is needed as well. The two keys are held in different places.
- Approving costs a sign-in. That is the point: it is a deliberate act, not a click in an open session.
- Not covered: a desk compromised while it serves its pages could show an approver one change and have the broker
  sign another (the broker's page does not show the change), and the proposer of a change is still vouched for by the
  desk alone. Per-person device keys (passkeys) would close the first; they remain a later option.
- A broker that loses its archive of published keys, together with the reconciler's archive, makes old proofs
  unverifiable: the reconciler then refuses and alerts rather than applying anything.
