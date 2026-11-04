# 0030. Records-key rotation, reminders, console grants, earlier reviews, core HA, any bastion, and a parent IGA

- Status: accepted (2026-11-04, maintainer, decision series P1 to P8). Builds on 0013 (topologies and nesting), 0015
  (the checking signer), 0018 (operations interfaces), 0020 (governance), 0021 (every granting key in the signer), 0022
  point 6 (built once, on the log) and 0023 (session constraints). Sets scope for 0.27.0 to 0.31.0.
- Context: a prior-art and gap review on 2026-11-04 compared KeyClerk with midPoint, Apache Syncope, OpenIAM, SailPoint,
  Saviynt, Entra ID Governance, Okta Identity Governance, Omada and One Identity, and with TUF, the C2SP witness
  protocol and OPAL. It found one high gap nobody had planned (the records key cannot be rotated or recovered), three
  medium ones (approvers are never reminded, grants made in the Keycloak console go unseen, access reviews come late)
  and three open scope questions (the approval sign-in level, what high availability covers, and how a parent IGA
  connects). The maintainer added two requirements: KeyClerk works with any bastion, and with any parent, central,
  decentral or sibling IGA.

## Decision
1. **The records key can be rotated and recovered (P1).** A rotation statement is signed by the old key, co-signed
   by the security officer and a root trust owner, and countersigned by the witness; followers and reconcilers move
   to the new key only through that chain. After a compromise, the same two people sign a statement naming the last
   checkpoint they still trust; followers refuse everything after it and the desk resumes above it in restore mode
   (0019). An optional TPM or HSM backend keeps the key out of any file. Built with step 8 in 0.29.0. Prior art:
   TUF's chained root rotation.
2. **Approvers are reminded, never handed an action (P2).** The event stream (0018 H5, #30) gains "approval waiting",
   "change expiring" and "escalated" events. They name the change and the next approvers and carry no link or button
   that approves (0010): the approver acts only in the desk after signing in. The deployment routes them to mail, chat
   or SOAR; KeyClerk holds no mail credential. In 0.27.0.
3. **Grants made around KeyClerk are seen (P3).** The reconciler reads the realm's admin events and raises a finding
   for every grant of a privileged role outside the managed set: realm-management roles and the client roles a
   deployment marks high-risk. Each finding goes to the security officer and the SIEM (#29) with the attribution the
   reconciler already reads. KeyClerk writes nothing to these: it never touches what it did not create. Orphans and
   shadow accounts in full stay with 0020 G7 in 0.32.0. In 0.27.0.
4. **Access reviews come two releases earlier (P4).** A minimal set in 0.29.0: a grant unreviewed for a configured
   number of months, or whose holder changed department, opens a signed review for its owner (0020 G1 trigger, G5
   owners); a revoke or a lapse ends the grant. The review record also accepts a parent IGA's certification as a
   signed decision (point 8). Holder bounds, SoD exceptions and the rest of 0020 stay in 0.31.0.
5. **An approval names its sign-in level (P5).** `approvals.acr` is required. `keyclerk init` proposes a value (from the
   realm's flows when it can read them) and asks for confirmation; a configuration without it is refused. `acr: none`
   is allowed only when written, and is a finding at every start. 0.27.0 carries an upgrade note for 0.26.x
   configurations.
6. **High availability covers the core signer too (P6).** The 0.28.0 profile has one promotion model for edge nodes and
   the core: a standby (for the core, a follower that holds the log) becomes active only by a witness grant or a
   two-person break-glass, and reports how; never on a timeout, so a network split cannot produce two histories. A
   core outage never cuts access (edges run on their horizons); it blocks new signed changes, a leaver's revocation
   among them, which is why the core is covered. Built once (0022 point 6).
7. **Any bastion (P7).** KeyClerk never talks to a bastion; the edge's adapter does. The edge protocol gains a
   capability vocabulary (ends sessions at lease end, assigns roles, injects credentials, records sessions, matches
   sign-in by subject, enforces time windows, a second key at session start) and an optional declaration in the edge's
   report, in the 0.27.0 wire release (#31), so an agent ports once. An adapter conformance profile says what every
   adapter does: apply a lease, remove it at its end, report a lease that ends early (0029 point 8) and the risky
   settings it finds at start. Before the vocabulary is frozen it is checked against at least three bastions' interfaces
   (Warpgate, Apache Guacamole, and HashiCorp Boundary or Teleport). Refusing a lease the edge cannot enforce stays with
   step 16 in 0.30.0 (0023).
8. **Any IGA as parent, through a generic interface (P8).** KeyClerk exposes a SCIM 2.0 target and its change API, so
   any IGA that provisions over SCIM can master scopes above it (midPoint through its SCIM connector; SailPoint,
   Saviynt or Entra alike), as 0013 point 4 allows. A parent's changes arrive as proposals under the parent's own
   adapter key and within a ceiling the child's officer signed; KeyClerk's policy, separation of duties and second key
   judge them as any other, so KeyClerk never becomes a pass-through. Mastership is recorded per fact class: a fact
   class has one master, and a change from anyone else to it is refused with who masters it. Siblings need nothing
   new: one writer per target and fact class (0013) keeps two IGAs from fighting, and they read each other through
   the identity visibility API (0018 H6, 0.33.0). Built with nesting (step 18) in 0.31.0, the same ceilings, horizons
   and fact classes, with a midPoint lab proof.

## Considered
- Rotation: build it in 0.27.0 with the witness (soonest, but SIEM and SOAR later), or a runbook only (cheapest;
  followers keep trusting a leaked key until someone acts).
- Reminders: KeyClerk sending mail itself (works out of the box, but a mail credential and an outbound channel to
  defend), or later with reviews (silent expiry until then).
- Console grants: report and remove (closes the bypass, but writes to objects KeyClerk did not create), or wait for
  0.32.0.
- Reviews: 0.30.0 ahead of session constraints, or 0.31.0 as planned.
- Sign-in level: a warning only, or leaving it to Keycloak's client policies.
- High availability: edges only in 0.28.0 with the core later, or the core restored from backup only (40 s measured).
- Bastions: declaration and enforcement together in 0.30.0 (the agent ports twice), or a second adapter proven in the
  lab now.
- A parent IGA: 0.30.0, before nesting (the way in for organisations that already run an IGA), or a dedicated midPoint
  connector first (tighter, vendor-specific).

## Consequences
A leaked records key has a signed way out, and a taken-over desk later cannot sign what the records do not allow
(0021). Approvals no longer lapse unseen, and access given around KeyClerk is reported the day it happens. Standing
grants are reviewed from 0.29.0. A second key is as strong as the sign-in a deployment confirmed. The core keeps
signing through a host loss without ever forking. Any bastion with an adapter can sit behind an edge, and what it can
enforce is declared, then enforced. An organisation that already runs an IGA keeps it as the parent; KeyClerk adds its
checks, its edges and its offline horizons below.
0.29.0 becomes the trust release (key custody, rotation, minimal reviews) and is the heaviest; 0.27.0 grows by points
2, 3, 5 and 7's declaration, each inside #29, #30 or #31.
