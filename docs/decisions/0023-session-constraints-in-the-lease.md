# 0023. Session constraints in the lease, enforced by edges that declare what their gateway can do

- Status: accepted (2026-10-24, choices S1 to S8), not built. Target 0.30.0, before the engine is
  published. The session-start approval (point 6) was accepted only after a prior-art review and an adversarial
  review, whose guards are part of this decision.
- Context: a lease says who may reach which target until when. Organisations governing remote access to sensitive
  systems also need to say how: how strongly the person signed in, which ticket the access serves, in which hours,
  whether a second session may run beside the first, and whether someone else must be involved. These are policy, so
  they belong to KeyClerk; enforcing them is the edge's work, through a gateway such as Warpgate or Teleport, which
  differ in what they can do. Facts that shaped the choices:
  - **Warpgate:** signs people in through one OIDC client per edge, so its sign-in level is per edge, not per target.
    It can hold every connection to a target until an approval arrives ("Require administrator approval for each
    connection"; with no approval cache period, every connection needs its own approval,
    warpgate.null.page/approvals). Exec and subsystem channels are dispatched before that approval resolves
    (github.com/warp-tech/warpgate/issues/2598). Warpgate 0.30 has no native limit on concurrent sessions.
  - **Teleport:** sets per-session MFA and hardware-key requirements per role. Moderated sessions, where a session waits
    until a moderator joins and can be terminated, are a Teleport Enterprise feature
    (goteleport.com/docs/zero-trust-access/authentication/joining-sessions/).
  - **Other products:** most approve a time window rather than a session (Teleport access requests, Entra PIM
    activation, Delinea, StrongDM). Per-start approval exists in CyberArk (one-time requests), BeyondTrust (approval
    before a session starts) and Warpgate.

## Decision
1. **One set of session constraints, one edge-format version (S1).** A lease, and a visit lease, may carry:
   - a required sign-in level;
   - a structured ticket;
   - time windows (days, hours and an IANA time zone) with a disconnect at the window's end;
   - session concurrency (one, or a second person may join);
   - the session-start approval of point 6.

   KeyClerk sets them per entitlement or risk class as policy, and carries them in the signed lease. They arrive
   together in one new bundle format (`kc-edge-bundle-v4`), so edges move once. They are built in stages: level and
   ticket first, then the session controls.
2. **Edges declare what their gateway enforces, in the signed enrolment (S3, S8).** The enrolment statement gains a
   capability declaration that lists, per constraint, whether the edge enforces it and how:
   - **at the gate:** before the session opens;
   - **corrected after:** for example a second session closed on the agent's next tick, seconds late.

   The declaration names the gateway and its version, and gives each corrected-after control its bound (for example at
   most 10 s, the agent's tick). Every tick, the edge checks that each control it declares at the gate is still
   configured (for example the hold on a target, the approval cache off). Drift suspends that target and is reported;
   a gateway upgrade or downgrade makes the edge declare again.

   KeyClerk refuses to issue a lease whose constraints the edge cannot enforce at the gate. The refusal says which
   constraint, why, and what would complete the request: another edge, or a policy without that constraint.
   - A deployment may allow a named weaker form (corrected after, or not enforced) per edge and per constraint.
   - That allowance is a governed change naming the edge, the constraint and an expiry.
   - It is carried in the lease, shown on the edge's page and recorded in the evidence. It is never silent.
   - Nothing degrades automatically.
3. **The sign-in level on a per-edge gateway (S4).** An edge whose gateway sets one level for the whole edge declares
   that level. A per-target requirement at or below it is met; one above it is refused (point 2). A per-edge level says
   nothing about how recent the sign-in is: a per-session fresh sign-in is a known gap on such gateways, stated in the
   declaration.
4. **The ticket (S6).** A ticket is structured: `{system, id, link}`.
   - Policy names the risk classes or entitlements that require one.
   - Approvers see it beside the change, and the lease carries it.
   - The edge's evidence for each session links the session to its lease and ticket.
   - Approvers and edges see the reference only, not the ticket's content.
5. **Time windows and concurrency.**
   - A window is part of the lease's signed bytes, expanded by KeyClerk into UTC intervals for the lease's whole life;
     the IANA time zone travels only for display. The edge needs no time-zone database, so an old one on an offline
     edge cannot shift a window after a daylight-saving rule change, and edge and KeyClerk agree by construction. The
     edge enforces the intervals with its own clock under the same floors as a lease's end (it never trusts a clock
     before the newest signed time), and ends sessions at an interval's end, offline too.
   - Concurrency "one" refuses a second session at the gate where the gateway can. Where it can only close the second
     session afterwards, that is the corrected-after form of point 2.
6. **Session-start approval (S5).** Where a gateway cannot hold moderated sessions, a deployment may require a second
   person to approve each session start live. Its name is **session-start approval**, never moderation, dual control
   or four eyes: it gates the start and nobody watches the session afterwards. It closely matches IEC 62443-3-3
   "explicit access request approval" for remote access (SR 1.13 RE(1)), not dual authorisation of actions. Its guards
   are points 7 to 14.
7. **One approval, one session.** The approval is a new statement purpose, `session-start`, beside approval and
   proposal. It covers:
   - the edge and node key id;
   - the lease id, person, target and role;
   - the ticket reference;
   - a single-use nonce the edge mints when the gateway holds the pending session;
   - a `not_after` measured in minutes.

   The edge accepts it once per nonce and refuses it for any other session, target, edge or purpose, and after
   `not_after`. A proof made for an ordinary approval never counts as a session-start proof. Where the edge learns of a
   held session by polling the gateway, the poll interval is part of the latency `not_after` must allow for.
8. **Never the desk alone.** The approval is verified at the edge, either by the edge itself against the broker's
   pinned issuer and keys, or by a countersign from the checking signer (the separate process that holds the records
   key) whose key the edge pins.
   Until one of these exists, session-start approval is not offered: a desk-made "approved" would rest on the desk's
   key alone, which KeyClerk's approvals-as-signatures design rules out.
9. **The approver sees what the edge holds.** A short code derived from the statement reaches the requester at the
   hold, at the gateway's own prompt where the gateway allows it, otherwise through the edge's local page; or the
   statement binds the gateway's own session id, which both requester and approver can read. The approver must match
   it. Which of these a gateway supports is part of its declaration (point 2). The approver sees the requester, target, ticket reference, and the source and
   client the edge reports.
10. **Online means a signed round trip.** The approval is valid only when it arrives within `not_after` after the
   edge's challenge, by the signer's signed time and the edge's nonce, never by the edge's wall clock. An offline edge
   refuses and says why and what completes the request. Targets that require session-start approval get no carried
   leases. Phoned unlock does not open them unless it is defined as this control's offline form, with the same binding
   to a held session.
11. **Who may approve.**
   - **Excluded:** the requester, by person and not merely by account; anyone from the requester's own organisation
     when the requester is external; the requester's reporting line.
   - **Sign-in:** the approver signs in phishing-resistant (the deployment's approval acr).
   - **At least two eligible approvers:** checked when the lease is issued, and the security officer is never the only
     one.
   - **Rate limits:** per requester and per approver.
   - **Load:** each approver's share of one requester's starts is reported to the officer.
   - **Timeouts:** fail closed after minutes, and nothing is approved by silence.
12. **At the gateway's hold.** The edge approves a held session only with a valid session-start approval for that
   session, and ends the session when the approval or the lease is revoked, within a stated bound. On Warpgate this
   means:
   - the agent is the only approver of held sessions;
   - the approval cache period is off;
   - no human administrator holds the approve permission; the edge checks this every tick where the gateway's roles
     allow it, and otherwise states it as a residual.

   On Warpgate 0.30, exec and subsystem channels on SSH targets are dispatched before the approval resolves, and a
   target has no switch to refuse them; the edge cannot intercept them, and closing the session afterwards is too
   late. So a Warpgate 0.30 edge declares session-start approval unenforceable for SSH targets until that is fixed
   upstream or such a switch exists, and point 13 forbids a weaker form. Other target kinds are declared only after
   their own check. A gateway without a hold point declares the control unenforceable (point 2).
13. **No escape on an escape.** Session-start approval is itself the weaker form of moderation. A deployment cannot
   allow a weaker form of it. Gateway drift on a target that requires it suspends that target, not only reports.
14. **What the evidence says.** The session's evidence carries the approval proof's hash and the nonce. Edges hold a
   pseudonymous approver key id, never the token. The control's assurance statement says what an auditor cannot
   conclude:
   - that the approver saw the session;
   - that the session did only what the ticket said;
   - that the approver was not colluding;
   - that the person who started the session kept working it.
15. **Visits on basic edges (S7).** A visit lease still needs an assured edge by default, by its ceiling and its own
   attestation. The security officer may allow visits on a basic edge in that edge's sealed ceiling: a named field in a
   new ceiling format (`kc-edge-ceiling-v3`), never a default. The allowance shows on the edge's page, in reports and in
   each visit's evidence. The edge's verifier applies the ceiling to visit leases as it does to leases.

16. **A rotation anchor pinned at enrolment.** The new enrolment statement also pins the public key of an offline
   post-quantum rotation anchor (SLH-DSA), chosen by the officer and held offline. In this release the edge only stores
   it. Later, the anchor co-signs key rotations and raises of the minimum format version with the officer; edges then
   refuse a rotation without a valid chain. Pinning it now means every edge enrolled from this release on can be moved
   to post-quantum keys however late, without a site visit (accepted 2026-10-24 with the crypto-agility choices Q5).

## Consider the opposite
- **Session-start approval adds freshness, not oversight.** The lease already carries a second key, the approver's
  own signature.
  This control fails closed exactly when access matters most (an outage, an incident, a cut network), and it gives a
  single unavailable approver a veto. Rubber-stamping is its documented failure mode.
- It was kept because some deployments need a person in the loop for each start where the gateway has no moderation,
  and an honestly named, narrowly bound control is better than none or a misnamed one. Points 10, 11 and 14 carry
  that cost into the open. Where real oversight is required, the answer remains a gateway with moderation.
- **A capability declaration makes the gateway's limits shape what KeyClerk may grant.** The alternative, issuing
  everything and letting the edge do what it can, is simpler and keeps access flowing, but it lets a lease promise a
  control nobody enforces. Refusing with a reason, plus a visible per-edge allowance, keeps the promise and the
  practice the same.

## Consequences
- Reviewed from the edge's side on 2026-10-24: the declaration's gateway version, bounds and per-tick drift check
  (point 2), UTC intervals for windows (point 5), the poll latency (point 7), a gateway-neutral code (point 9), and
  session-start approval unenforceable for SSH targets on Warpgate 0.30 (point 12) came from that review.
- New formats: `kc-edge-bundle-v4` (the constraints in leases and visit leases), a capability declaration and the
  rotation anchor's public key in the enrolment statement (a new officer statement version), `kc-edge-ceiling-v3` (the visit allowance), and the
  `session-start` statement purpose. Edges on the current formats keep working until they move. Conformance vectors
  for every refusal in points 2, 5, 7, 10 and 15 come with the formats.
- The desk shows each edge's declaration and allowances, refusals with their reasons, and the session-start approval
  queue with its code, rate limits and approver load.
- The engine is published after this release, so the first public engine ships these formats.
- Point 8 depends on the edge verifying broker tokens itself or on the checking signer. Session-start approval is
  offered only once one of them is built.
