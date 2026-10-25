# 0010: Person-first visits, access in hours, and how settings are shaped

- Status: accepted (2026-10-23): the person is the unit; the order of work is person-first visits, then access in
  hours, then the choices on recovery and break-glass.
- Date: 2026-10-23
- Supersedes: decision 0009 section 1 for visit parties and vehicles (the rest of 0009 stands)

## Context
Visits as built in 0.10.0 to 0.12.0 hang off one driver or lead, with passengers attached to the visit and vehicles
attached to that driver. Real visits do not look like that. A delegation for an on-site meeting or event has people who
registered beforehand, people who were invited but did not register, people who register at the front office, and
unregistered companions. They come together or apart, on foot or in several vehicles, at different times. Each of them
has their own code, badges, kit and gate history.

The same admission is wanted for systems, for hours rather than days: an external support engineer for an afternoon, or
a colleague who needs to read something for an hour instead of having it looked up and sent.

How capabilities and settings are shaped was set at the same time (2026-10-23): everything a deployment may want is
possible, switched by configuration as code and decided by policy, and the shipped defaults are what we find secure.
Deployments differ too much for one fixed behaviour to fit them all, and a capability nobody can switch off, or a
default nobody has judged, is where insecure installations come from.

## Decision

### 1. The person is the unit of a visit
- A **visit** is the meeting or event: place, window and margins, purpose, host (receives the guests), organiser, and
  **escorts** (internal staff who accompany guests that may not walk unescorted).
- A **delegation** is optional: the group the attendees belong to, with their organisation and a contact.
- An **attendee** is one person, with:
  - a registration state: `registered` (a person record, self-registered beforehand), `invited` (expected by name,
    not registered yet), `registered-on-site` (registered at the front office on arrival, identity checked there),
    or `unregistered` (a label and no identity: never more than an escorted visitor badge);
  - an expected arrival time, their own QR code (when registered), badges, kit and escort;
  - their own gate history (arrived, entered, left), timers and confirmations.
- An **arrival** is an event of one or more attendees: on foot or in a vehicle. A vehicle belongs to an arrival (its
  driver and the attendees in it); two cars are two arrivals. The plate stays a keyed digest and three characters.
- The policy decisions (act, entry, timers, see, unescorted, badge) stay per person and keep their names.

### 2. Access in hours, the same admission for systems
- A **session** admits a person to a system for hours: a sponsor, a window, a narrow scope (a group or an entitlement,
  read-only by default), an end that removes the access and ends the sessions. External engineers sign in through their
  own federated identity or a guest passkey; nobody gets a password.
- Memberships may be given in hours as well as days.
- Policy sets the maximum length and the keys per class; the shipped defaults are low 8 hours without a second key,
  elevated 4 hours with a second key, privileged 1 hour with a second key.

### 3. Settings: capable by policy, secure by default
- **Settings** are configuration as code, every one tunable.
- **Rules** are Rego: they decide each request from the facts and the settings in force.
- **Profiles** are named intents ("strict site", "standard office") that expand into a coherent set of settings; the
  expansion is visible, every setting stays overridable, and Rego refuses combinations that defeat each other.
- Capabilities a deployment may want later (calendar sync with Exchange, Teams, Google or CalDAV; presence by badge
  readers, Wi-Fi, BLE or private 5G; plate recognition; even face recognition) are possible only this way, off by
  default, and turning one on carries its purpose, retention and legal basis in configuration.

### 4. KeyClerk is not an identity provider (position; the choices on recovery follow)
KeyClerk decides who may do what and when; the broker (Keycloak or another OIDC provider) holds credentials, passkeys and
sessions. Reasons: approvals are signed by the broker independently of the desk (0006), so a desk that also issued
identities would remove that separation; passkey verification, attestation, sessions and recovery are a large
security-critical surface; a deployment must be able to replace the broker behind a fixed claims contract. KeyClerk owns
the recovery *lifecycle* (who may recover, the two people, timers, evidence) as an admission and tells the broker what to
do (a one-time passkey enrolment); the broker does the cryptography.

### 5. How guests get in: invitations, not open registration (proposed; its choices are still open)
The question (2026-10-23): how does the organiser get what is needed from the visitor or the remote engineer,
and how do we stop someone with the public address from self-registering, picking a random host and hoping an unaware
employee clicks yes?
- The organiser registers the visit and invites people. Each invited attendee gets a single-use invitation link that
  expires, signed by the desk and bound to the visit and that attendee's place in it. Self-registration (an account
  and passkey at the broker, evidence for the checker) happens only through that link. The registrant never picks the
  host, the visit or the time: the invitation fixes them.
- An open request form (no invitation) is off by default. A deployment that turns it on sends a request to the place's
  front office queue, never straight to a named employee; the named contact is asked inside the desk, with the risk
  shown, and an unknown requester needs a second key.
- Nobody approves from a link in a message. Notifications carry no action, only "open the desk"; approving is the
  signed step-up of 0006, showing who asked, from where, and whether this is a first contact.
- Risk is a Rego decision with signals: requests per host per day, per address, per mail domain; a first-time
  requester; a mail domain that does not match the delegation's organisation; outside working hours; a host who never
  hosts; the same identity in two overlapping visits at different places, or already on site elsewhere; an invitation
  opened from many addresses; failed scans. High risk asks a second key or refuses, and alerts the security officer.
- Limits: an invitation is redeemed once; redemptions per address and per host per day are capped; scans already are.
- Checked evidence (0009 section 3) is required per visit kind and zone before an attendee counts as registered.
- The remote engineer follows the same path with a session (section 2) instead of a visit.

## Consequences
- Visit records change shape in 0.13.0 (attendees, arrivals, escorts, delegation). Records made by 0.10.0 to 0.12.0
  are read as they are (the history guard forbids rewriting them): their parties become attendees when read.
- Sessions and memberships in hours follow in their own release.
- Profiles are a later release; until then settings carry their defaults in code and configuration.
