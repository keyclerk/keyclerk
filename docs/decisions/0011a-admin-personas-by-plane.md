# 0011a: Admin personas by plane (amends 0011)

- Status: accepted with the adversarial review's five changes (2026-10-23; change 1 built first). The question that
  prompted it: admin of what? A person may be a domain admin in AD but not in Entra ID, or an admin in Keycloak but not
  in KeyClerk. The proposal was researched against best practice, known pitfalls and zero-trust guidance first, then
  reviewed adversarially.
- Date: 2026-10-23

## Evidence (summary of the research of 2026-10-23)
- Microsoft's enterprise access model: a control plane (identity and what controls it), a management plane (enterprise
  IT), a data and workload plane (per workload), user and app access; a lower plane never controls a higher one.
- Microsoft for Entra ID: cloud-only privileged accounts, never synced from AD; privileged devices; just-in-time
  activation with phishing-resistant sign-in; few Global Administrators; two cloud-only emergency accounts.
- CIS Controls v8 5.4 and NIST SP 800-53 AC-6(2): dedicated admin accounts; mail, browsing and productivity only from
  the non-privileged account.
- Clean source: a device that is compromised gives away every account used on it.
- Incidents: help-desk resets of admin accounts (Scattered Spider), a test tenant account without MFA (Midnight
  Blizzard), synced on-premises admins reaching the cloud, forged tokens from a stolen signing key (Storm-0558).

## Proposal
1. **Systems and planes.** Every catalogue entitlement names its system; every system names its plane and, in the
   control plane, its trust root (configuration): `control` (identity providers, KeyClerk itself, the key and signing
   store, the certificate authority), `management` (hypervisors, servers, network), `workload` (one application or
   team), `user` (ordinary use).
2. **Personas.** A person has a daily account (user plane) and, only when needed, admin personas: one per plane, and
   in the control plane one per trust root (AD, Entra ID, Keycloak and KeyClerk are separate trust roots; a deployment
   may group roots that share their fate). Each admin persona states its plane, its trust roots and its device class.
3. **Rules (identity.rego, compiled in).**
   - A right on a system of plane P is held only by an admin persona of plane P (and, in the control plane, of that
     system's trust root); a daily account holds only user-plane rights, whatever the class.
   - An admin persona holds no right of another plane: never down-plane, never up-plane.
   - Privileged rights are eligible, not standing: memberships in hours with a second key (0010 section 2); a standing
     privileged membership is refused by default.
   - Nobody holds a control-plane right on KeyClerk and approves their own access (already: no self-add, second keys
     with standing).
   - Caps per tenant: control-plane admin personas at most a set number (default 5); above it, a warning to the
     security officer.
4. **What KeyClerk tells the broker.** Each admin persona's plane and device class go out as claims, so the broker
   and the enforcement points can require the right device and a phishing-resistant key; KeyClerk does not enforce
   sign-in itself.
5. **Lifecycle.** A leaver ends every persona at once; a mover ends or flags the plane-specific personas; admin
   personas are reviewed on their own, more often; recovery of an admin persona is never a help-desk reset, because a help-desk reset is how the incidents above took
   admin accounts over.
6. **Break-glass is not a persona.** It stays the deployment's separate, monitored emergency path, outside the
   personas and their rules, so that it still works when they fail.
7. **kai in the demo:** `idp:bb11-kai` (daily, user plane), `adm0:kc:bb11-kai` (control plane, trust root Keycloak and
   KeyClerk), `adm1:bb11-kai` (management plane).

## Adversarial review (2026-10-23) and what changes
An adversarial review found sixteen problems, eight of them high. The two most important hold against the code as
released in 0.14.0 and are known gaps until fixed:
- The persona check runs only on memberships that name an account. (Checked against the code: an included group is
  raised to the class of the group that includes it, so a daily account in it is refused already, and a privileged
  group never takes a rule; what remained open was a surge and an account with no stated purpose, both closed by
  judging every effective member when enforcing.)
- KeyClerk's own powers (the root, a deputy, a second key) are compared per person, not per account, so the root's
  daily browser session holds root power at the desk.

Changes to the proposal before acceptance:
1. **Judge every effective member, by account.** Persona and plane are checked on effective membership (direct,
   included, by rule, by surge, agents), not only when a membership is made. The root holder, a delegate, an approver,
   an agent's director and a workload's owner are compared by account: for a group whose rights are of plane P, the
   actor and the approver must be the plane-P admin persona of that trust root. An account with no stated purpose
   holds no privileged or control-plane right.
2. **Plane fails closed.** A system with no plane counts as control. Plane is derived from what a system hosts or
   controls: whatever hosts, builds or configures a control-plane system (the nodes, the backups, the CI that builds
   the policies, the configuration repository) is control plane. Trust roots declare what they depend on (Keycloak can
   sign approvals for KeyClerk, so a Keycloak admin is control over KeyClerk too); caps count across that. A
   control-plane right is never classed below elevated. KeyClerk, the broker's realm management and the signing store
   are control plane by definition.
3. **KeyClerk's own control surface is governed.** The reconciler's credential is a control-plane workload in the
   records. Lowering a plane or a class, and every weakening setting (privileged_needs_admin off, machines in
   privileged groups, higher caps), need the security officer's key and alert. A drift report flags broker accounts
   with realm management, groups KeyClerk did not write, and accounts not in the records.
4. **Claims become enforceable.** Before writing an admin persona's membership, the reconciler checks the broker:
   control-plane clients require a passkey, tokens are sender-constrained and live at most 10 minutes, removal ends
   sessions. The device class comes from attestation at sign-in, not from KeyClerk. A control-plane group that has not
   been reconciled within N minutes expires at the broker (dead man).
5. **Against standing access and fatigue.** Privileged hours are capped per persona per week; a renewal within 15
   minutes of the end is a continuation and needs a fresh key; approvals per approver per day are capped; one
   extension without a new key within the cap; time comes from the server. Until hours exist (0010 section 2) the
   interim is stated: privileged memberships at most 1 day with a second key. A mover's plane personas end by default
   (flagging is a setting). Admin personas have their own credentials and their own recovery (two people, including the
   security officer); an unused admin persona is suspended after 30 days. A one-person tenant uses an honest
   single-operator profile (a delay and an out-of-band notice), never an invented second person. Control-plane admin
   personas are capped at 4 per tenant, refused above. Break-glass never creates memberships; every use alerts and is
   reviewed within 24 hours.

Out of scope for personas, said plainly: a workload holding control-plane rights (the lesson of Midnight Blizzard) and
validators not checking scope (Storm-0558) are fixed by the workload and token rules, not by personas.

## Built
- Change 1 (0.15.0): identity.persona_rule (off, warn by default, enforce). Enforce judges every effective member by
  persona (an account with no stated purpose holds no privileged right), uses the root's and a deputy's power only from
  the account the role names and, for a privileged group, only from an admin persona, and counts a second key for a
  privileged group only from an admin persona. `python -m keyclerk.delegation --persona-impact FILE` lists what
  enforce would change.
