# 0009: Visits with vehicles, passengers and kit; checked evidence; access over time

- Status: accepted (the decision record below overrides the text above where they differ)
- Date: 2026-10-22
- Decider: maintainer

## Context
KeyClerk grants digital and physical access to people. A real site visit is more than a person: a visitor arrives in
a vehicle, with passengers (some registered, some not) and kit (laptops, tools, goods, documents), for an
appointment with a host. Entry depends on evidence (an ID, a permit, a certificate, a clearance) that someone must
check. And people ask questions over time: when was this person last in, what could they reach on a given date, and
when are they due again.

What KeyClerk already has, and this builds on:
- leases for externals (with `proofs`);
- places, zones and checkpoints (access_paths, Restricted needs two people);
- the event log (keyclerk-event-v1), append-only, pseudonymous, read forwards and backwards;
- derived access state (state is a function of the signed records, the time and the evidence);
- signed approvals (0006) and policies compiled into the engine (0008).

The worked example this must handle:
- Driver X books a meeting from 13:00 to 14:00. They may arrive from 11:00 and stay until 16:00.
- X arrives in a vehicle with a recorded plate, carrying two laptops and a backpack, with one passenger.
- X registered through self-service and holds a QR code: the vehicle and X go in on the QR.
- The passenger is not registered. They may enter, but only after queueing at the front office for a temporary
  visitor badge, and they must show that badge.
- Anyone with a phone may scan X's QR and learn "may enter unescorted: yes or no". Nothing more.
- If X needs a Restricted zone, X also collects a RESTRICTED badge at the front office. The passenger can never get
  one: they are unregistered.
- On X's arrival, the organiser and/or host get a notification and confirm it.
- 15 minutes later, the organiser or host confirms they have X with them. Five minutes after a missed confirmation,
  X's access is revoked and the visit is flagged (decided: suspended and flagged, D3).

## Decision

### 1. Records
> Superseded in part by 0010 (2026-10-23): visits are person-first. The parties-and-vehicles shape below (one driver
> or lead, passengers, vehicles on the visit) is replaced by attendees, arrivals, escorts and an optional delegation.
> Badges, claims and the rest of this section stand.

- **visits**:
  - `visit_id`, `host` and `organiser` (anchors);
  - `place`, `window` (start, end) with `early` and `late` margins from policy data;
  - `purpose`, and `zones` requested.
  A visit is the only thing that admits someone on site. It is made like any change: proposed, checked, approved
  when the policy asks for a key.
- **visit parties**: who comes on the visit.
  - The driver or lead, a person record, registered.
  - Passengers: each one `registered` (a person record) or `unregistered`, which is a count with an optional name
    and no identity. An unregistered passenger can never hold more than a temporary visitor badge.
- **vehicles**:
  - Plate as a keyed digest plus the last characters for display, so the record does not leak the plate.
  - Make, model and colour as free text, for the guard.
  - Linked to a visit, never to a person forever.
- **kit**:
  - Items by class: IT device, tool, compliant goods, documents, media.
  - Each item has a count and an optional serial digest.
  - Classes come from policy data, with rules per zone, such as "no media into Restricted".
- **credentials** (badges):
  - `badge_id`, `kind` (visitor or restricted), `holder` (a party), `issued_by` (the place's front office; a RESTRICTED badge also names a second person, D4), `from`, `to`
    (capped by the visit window), returned or not.
- **claims** (checked evidence), see section 3.

### 2. Decisions by policy (Rego, compiled in, as in 0008)
- `entry`:
  - Input: party, vehicle, kit, time and checkpoint.
  - Output: allow, plus the conditions: escort, front office, badge kind needed.
  - In the example:
    - the driver passes on the QR inside the window;
    - the vehicle passes with the driver;
    - the passenger is sent to the front office for a visitor badge;
    - X's Restricted zone needs a RESTRICTED badge;
    - an unregistered party gets "never".
- `unescorted`:
  - The scan answer for anyone with a phone: yes or no, and until when.
  - No name, no purpose, no host. The QR is a signed short token naming the visit and party, not a person's data.
  - Guards check it online (revocation seen at once) and fall back to the signature when the site is cut off,
    saying so (D2). The phone scan is online only.
- `badge`: who may receive which badge kind, and for how long.

### 3. Checked evidence: one contract for every checker
A **claim** says "this party holds this":
- `claim_id`, `subject`, `type` (from a catalogue in policy data, for example `id-document`, `site-badge`,
  `written-permit`, `signed-template:<name>`, `degree`, `certification:<scheme>`, `accreditation`,
  `clearance:<level>`);
- `evidence` (a digest and a reference, never the document in the records);
- `checked_by` (an anchor) and `checker_kind`: a person in the checker role, an agent, a workload, an API source (HR,
  a skills register, a group lookup) or a workflow;
- `method`, `level` (assurance), `checked_at`, `valid_until`, `recheck_after`, and `result` (pass, fail or expired);
- the checker's signature: a broker proof for a person (as in 0006), a workload's own key for agents and workloads.

The rules:
- The policy names, per access (a zone, a group, a visit kind), which claim types are required, at what level and
  how fresh.
- Access waits until the claims hold.
- When all claims hold, the onboarding package (as for leases) is sent.
- An expired claim makes the access stop, like any rule (0008: judged as things stand).
- A checker never checks their own claim. An agent or workload checker is limited to the claim types the policy
  gives its kind.

A validator that queries an outside system (HR, a skills register) is a checker of kind `api-source`: same contract,
same signature, same expiry. Its answer is a claim, so the policy never calls out at decision time and KeyClerk keeps
running offline (0008).

### 4. Timers that re-check their reason
- On arrival (the first `entry` allow of a visit), notifications go to the organiser and host, who acknowledge them.
- After `confirm_after` (default 15 minutes), the host or organiser confirms that the guest is with them.
- After `grace` (default 5 minutes) without that confirmation, the party's access and badges are suspended and the
  visit is flagged for the officer.
- Each step re-checks, when it fires, that its reason still holds: no confirmation recorded, the visit not ended, the
  party still inside. A timer that acts on a reason it no longer checks acts on a stale world: workflow engines,
  Keycloak Workflows among them, show the failure when a step scheduled hours ago fires after the situation changed.
- Timers live in the engine's own schedule, are evaluated by the reconciler loop, and are recorded as events.

### 5. Access over time
- **Back** (was, last): any past instant answers from the records, which are append-only and signed, folded at that
  time. "Last in" answers from the event log: KeyClerk keeps its own compact `last_seen(person, place or client)`,
  fed by checkpoint and broker events. It does not depend on the broker's event retention.
- **Forward** (next): from the records, never predicted. The next visit window, lease window, membership start and
  claim expiry. "When will they access again" means "when are they scheduled to", and says so.
- The same views for visitors, by party: registered or not, with the vehicle.

### 6. Identity observability (IVIP, the useful part)
In order of value for a site running KeyClerk:
1. **Drift**: what the records say against what the broker has. The reconciler holds both already.
2. **Dormancy**: grants unused for N days, from `last_seen`, including leases never used.
3. **Explain**: why someone can reach something, through record, approval, group and path. Partly there in
   `--explain`.
4. **Peer outliers**: grants a person holds that nobody else in their unit or role holds.
5. **A per-person timeline**, viewed by role, with every view logged.

Shared Signals (CAEP) events out are a later step.

## Privacy
- Store digests and results, not documents.
- Visitors and plates are pseudonymous in events.
- `last_seen` is aggregated per day, with a stated purpose and retention.
- The phone scan reveals only yes or no.
- Unregistered passengers are a count, not people.

### 7. The same front door for digital access
Self-registration on a portal, finding a host (a person, or a meeting or request id), uploading evidence for a checker,
waiting for a decision and receiving an onboarding package are the same steps whether the target is a site visit, a
federation partner, VPN access or a public application. An **admission request** names its target kind
(`site-visit`, `federation`, `vpn`, `app`) and the policy decides per kind which claims, which sponsor and which
window apply; the outcome is a lease or visit for that target.

### 8. Views (observability you can see)
- A manager delegating: a tree of what they handed on, to whom, how deep, until when.
- A host admitting visitors: a timeline of the visit (window, arrival, confirmations) with the party, vehicle and kit.
- A realm admin: how personas connect (a person's accounts, through which identity provider), and how they relate
  in scope (groups, tenants), place (sites, zones) and time (windows, last seen). Prior art to study first: Elimity.
Every view shows only what the viewer may know (need to know), and opening a person's view is logged.

Built so far: the persona graph (0.8.0, keyclerk/policy/view.rego) and the delegation tree (0.9.0,
keyclerk/policy/tree.rego). The tree shows each delegation at the moment picked: delegate, group, powers, class, how
many more levels it may pass on, who made it, its window, its state (in force, starts later, grace period, ended,
revoked, broken above) and the memberships made under it still in force. A viewer and the root see all of it; a
deputy sees what they hold or held, everything below it and the chain above it back to the root, never a sibling's
branch. A delegation that stopped more than 30 days before the moment is left out.

Visits, first slice (0.10.0, keyclerk/visits.py and keyclerk/policy/visits.rego with four decisions: act, entry,
timers, see):
- Records `visits` (place, host, organiser, purpose, meeting window and the opens and closes margins fixed at
  registration, zones asked for, parties, vehicles with the plate only as a digest keyed by the desk's own key and its
  last three characters, kit by class) and `visit_events` (arrived, entered, acknowledged, confirmed, reminded,
  suspended, left), both append-only under the history guard.
- Desk actions register_visit (host or organiser; the host is someone of the tenant), record_entry and
  record_departure (the place's front office or steward), acknowledge_arrival and confirm_guest (host or organiser).
  An entry is decided by `entry`: in the worked example the driver passes on the QR with the vehicle, the
  unregistered passenger is sent to the front office for a temporary visitor badge and then passes escorted, a
  vehicle passes only with its driver, a Restricted zone sends the driver for a RESTRICTED badge and refuses the
  passenger for good.
- The first entry notifies the host and organiser. The desk's timer thread asks `timers` every 30 seconds: a reminder
  15 minutes after arrival, a suspension flagged for the officer 5 minutes later, each only while its reason holds.
- GET /visits and GET /visits/{id}?at= (who comes, vehicle, kit, a day strip, the timeline with the steps ahead,
  what the gate says now, what you may record), shown to the host, organiser, the place's front office or steward,
  the guest themselves, a viewer and the root (`see`); every look is logged.
- Not yet: checked claims and the onboarding package (section 3), last seen (D6).

Badges (0.12.0; D4): records `badges` (visit, party, kind visitor or restricted, the badge number only as a digest
keyed by the desk's own key and its last three characters, issued_by, approved_by, from and to inside the visit
window), append-only. `badge` in visits.rego judges each badge as made: only the place's front office or steward
issues one; an unregistered passenger never receives a RESTRICTED badge; a RESTRICTED badge waits for a second key
from another front office person or the steward, through the desk's usual pending change and approval (approval
proofs included). At the gate a visitor or RESTRICTED badge counts only when one was issued to that party and holds
now, not returned (`visits.badges_required`, default true). return_badge records a badge-returned event.

Person-first visits (0.13.0, decision 0010): attendees with their own state, expected arrival, escort and kit; escorts
on the visit; an optional delegation; vehicles announced on the visit and named by an arrival, or a plate typed at the
gate; a vehicle comes in only with a registered driver. add_attendee (host, organiser or front office) and
register_on_site (front office; links an invited or unregistered attendee to their account and issues a code) are
events. Escorts are notified on arrival, may acknowledge and confirm, and see the visit.

The QR code and the phone scan (0.11.0, keyclerk/qr.py; D2):
- A code is `kq1.<payload>.<signature>`: the visit id, the party, a serial, the expiry (the visit's close) and the key
  id, signed with the desk's own Ed25519 key (qr.key in the store, never in the records). No name, no purpose, no host.
  The records keep only a digest and the serial (`qr-issued` events); the code is made again on demand, as Ed25519
  signatures are deterministic.
- Each registered guest gets a code when the visit is registered; issue_qr (the guest, host or organiser) makes a new
  one and the old one stops working. GET /visits/{id}/qr/{party} gives the code, its link and the image.
- The QR is a link to the scan page (`<base>/#/scan/<code>`), so any phone camera opens it. GET /scan/{code} needs no
  sign-in and answers only yes or no and until when, checked online now and decided by `unescorted` in visits.rego:
  yes needs the current code, a registered guest who passed the gate, not suspended, not left, inside the window.
  Scans are rate limited per address (`visits.scan_per_minute`) and logged without the code.
- A guard records a QR entry with the scanned code (`token`): the desk checks it online (signature, expiry, the
  latest serial) and `entry` counts a QR only when it checked out (`visits.qr_required`, default true). A signed-in
  front office scanning with their phone gets a button to record the entry on the scan page itself.
- Offline: GET /qr-key publishes the public key; `python -m keyclerk.qr verify CODE KEY` checks signature and expiry
  and says that a new code, a suspension or a departure since it was issued is not seen.

## Decision register (the choices open at the time)

| # | Decision | Options | Depends on | Notes |
|---|---|---|---|---|
| D1 | One admission spine for site visits and digital access (federation, VPN, app) | one admission request with a target kind; separate flows per kind | | The same steps count for digital access |
| D2 | Where the QR and scan answer are checked | signed offline token (works without network); online lookup (revocable at once); both | D1 | Guards may be cut off |
| D3 | A guest not confirmed in time | revoke and flag; suspend and flag | D1 | The example says revoke |
| D4 | Who issues badges | a front office role per place; the place's steward | D1 | |
| D5 | Checked evidence for staff too (a degree, a certification for a group) | yes, same contract; externals only | D1 | Validator may later be a workflow or API source |
| D6 | Detail of last seen | per day per person and place or client; per event with short retention | | Staff monitoring: purpose and retention |
| D7 | Order of the views | realm admin graph first; delegation tree first; visit timeline first | D1 | Research on visual prior art pending |
| D8 | Where the views run | in the desk (same sign-in, need to know); a separate read-only console | D7 | |

## Decision record (accepted 2026-10-22)

| # | Decision | Outcome | Status |
|---|---|---|---|
| D1 | One admission spine for site visits and digital access (federation, VPN, app) | one admission request with a target kind (site-visit, federation, vpn, app); policy varies claims, sponsor and window per kind, amended: every decision in 0009 is OPA: admission, entry, unescorted scan, badges, required claims and checker scope, timer reasons, and what each view may show are Rego compiled into the engine and run in process (as decision 0008); code only gathers facts | resolved |
| D2 | Where the QR and scan answer are checked | both: short-lived site-signed token (visit, party, validity inside the window); guards check online by default (sees revocation), fall back to the signature when cut off and say 'offline, revocation not checked'; public phone scan online only, yes/no | resolved |
| D3 | A guest not confirmed in time | suspend and flag: access and badges stop at once, the officer is flagged; a late host confirmation plus the officer's key lifts it, the visit record stays | resolved |
| D4 | Who issues badges | front-office role per place (listed on the place, appointed by the steward, steward as fallback); a RESTRICTED badge needs a second person: steward, deputy or officer | resolved |
| D5 | Checked evidence for staff too (a degree, a certification for a group) | yes: claims apply to staff too (a degree, a certification, a skill or HR fact for a group), same contract and checkers | resolved |
| D6 | Detail of last seen | two tiers: per-day summary per person and place or app kept about 13 months (views, dormancy); exact pseudonymous events kept about 30 days, officer-only, every look logged | resolved |
| D7 | Order of the views | admin persona graph first (ego-centred: accounts by IdP, groups/tenants and sites/zones as compound boxes, validity and last seen on edges, search-first, need-to-know filtered server-side); delegation tree reuses it next; visit timeline after visit records exist | resolved |
| D8 | Where the views run | in the desk, as API endpoints; OPA decides what each viewer may see; same sign-in, DPoP and logging; the console stays the local operator tool | resolved |

### D1: One admission spine for site visits and digital access (federation, VPN, app)

- Status: resolved (2026-10-22 21:57)
- Context: options: one admission request with a target kind; separate flows per kind; notes: the same steps count for digital access
- Decision outcome: "one admission request with a target kind (site-visit, federation, vpn, app); policy varies claims, sponsor and window per kind", amended: every decision in 0009 is OPA: admission, entry, unescorted scan, badges, required claims and checker scope, timer reasons, and what each view may show are Rego compiled into the engine and run in process (as decision 0008); code only gathers facts, because every one of these is a policy choice a deployment must be able to read, test and change in one language, and a rule kept in code as well drifts from its copy (decision 0008)
- Unblocked: D2, D3, D4, D5, D7

### D2: Where the QR and scan answer are checked

- Status: resolved (2026-10-22 21:55)
- Context: options: signed offline token (works without network); online lookup (revocable at once); both; depends on: D1; notes: Guards may be cut off
- Decision outcome: "both: short-lived site-signed token (visit, party, validity inside the window); guards check online by default (sees revocation), fall back to the signature when cut off and say 'offline, revocation not checked'; public phone scan online only, yes/no", because a site must keep working when its wide-area link fails; online default keeps the 5-minute revoke effective; offline answer states its limit

### D3: A guest not confirmed in time

- Status: resolved (2026-10-22 21:56)
- Context: options: revoke and flag; suspend and flag; depends on: D1; notes: The example says revoke
- Decision outcome: "suspend and flag: access and badges stop at once, the officer is flagged; a late host confirmation plus the officer's key lifts it, the visit record stays", because same effect at the gate as a revoke; revoke is for cause and voids everything under it; suspensions already exist with key-gated, signed lifts

### D4: Who issues badges

- Status: resolved (2026-10-22 21:56)
- Context: options: a front office role per place; the place's steward; depends on: D1
- Decision outcome: "front-office role per place (listed on the place, appointed by the steward, steward as fallback); a RESTRICTED badge needs a second person: steward, deputy or officer", because stewards are rarely at the desk; Restricted keeps its two-person rule (access_paths)

### D5: Checked evidence for staff too (a degree, a certification for a group)

- Status: resolved (2026-10-22 21:56)
- Context: options: yes, same contract; externals only; depends on: D1; notes: Validator may later be a workflow or API source
- Decision outcome: "yes: claims apply to staff too (a degree, a certification, a skill or HR fact for a group), same contract and checkers", because the validator may later be a workflow or an attribute check against HR, skills or groups, and staff evidence needs the same contract for that; taken as the default

### D6: Detail of last seen

- Status: resolved (2026-10-22 21:57)
- Context: options: per day per person and place or client; per event with short retention; notes: Staff monitoring: purpose and retention
- Decision outcome: "two tiers: per-day summary per person and place or app kept about 13 months (views, dormancy); exact pseudonymous events kept about 30 days, officer-only, every look logged", because dormancy and day-level time travel without hour-level monitoring of staff; investigations keep a short exact window

### D7: Order of the views

- Status: resolved (2026-10-22 21:55)
- Context: options: realm admin graph first; delegation tree first; visit timeline first; depends on: D1; notes: Research on visual prior art pending
- Decision outcome: "admin persona graph first (ego-centred: accounts by IdP, groups/tenants and sites/zones as compound boxes, validity and last seen on edges, search-first, need-to-know filtered server-side); delegation tree reuses it next; visit timeline after visit records exist", because data exists today; it is the view most specifically asked for; prior art draws ego graphs (Teleport, SailPoint), none shows time or place: KeyClerk's differentiator; whole-estate graphs do not scale (midPoint)
- Unblocked: D8

### D8: Where the views run

- Status: resolved (2026-10-22 21:58)
- Context: options: in the desk (same sign-in, need to know); a separate read-only console; depends on: D7
- Decision outcome: "in the desk, as API endpoints; OPA decides what each viewer may see; same sign-in, DPoP and logging; the console stays the local operator tool", because per-person need-to-know already lives in the desk; contractually API-enabled front end lets other front ends draw the same views

## Amendment (2026-10-23): visits live outside the signed records

An adversarial review of 2026-10-23 found, as one critical and one high finding, that visits, their events and badges sat in the signed records: every
revision copied every visitor's name, organisation, purpose and plate tail, nothing was ever deleted, and the records
grew until the desk would stop loading them (above 16 MB). Changed in the engine after 0.15.0:
- A visit with its attendees, events and badges is its own file in the desk's store (`visits/<visit id>.<hash>.yaml`),
  written ahead of a line in the desk's signed, hash-chained log that vouches for its hash. A visit change makes no new
  records revision; the records keep access only (grants, groups, delegations, leases).
- The log names visits by id only: no names, organisations, purposes or plates.
- `visits.retention_days` (default 30) after a visit closes, the timer erases its file; the log keeps one line with the
  visit id. The log stays verifiable; the content is gone.
- At start the desk sets aside visit files no log line vouches for (a crash between writing and logging) and refuses to
  start when a vouched file is missing or changed.
- A store written by 0.15.0 or earlier keeps its visits in the records until it is seeded again; their copies in old
  revision files and log lines stay until then. A migration that moves them and purges the old copies is to be written
  before any store with real visitors exists (today only test stores do).
