# Use case: a building's data owner manages access to a central system, inside the system owner's envelope

Status: use case and gap analysis (2026-10-23), for the operator to choose what to build. Names are examples.

## The story
A camera surveillance system runs centrally for the whole organisation. Its **system owner** (the workload admin who
runs the central camera server) does not decide who may watch the cameras of each building. For building A, a
**data owner** is made responsible: they add the people they have validated and trust, and remove them. At least one
**deputy** (a colleague) holds the same power, so access does not stall when the data owner is ill or on leave. The
system owner trusts the data owners to give access only to people who need it, and is not asked about each person.

## Roles, and how KeyClerk already models them
| Role | What they decide | In KeyClerk today |
|---|---|---|
| Root trust owner | who owns which system | the root role; delegations start here |
| System owner (workload admin) | what access to the system exists, its classes and the limits every building works within | owner of the system's catalogue entitlements; a delegation over the system's group tree (subgroups, delegate) |
| Data owner of building A | who in building A may use the system | a delegation with the members power over the building A subtree, narrowed by the system owner's delegation |
| Deputy | the same, when the data owner is away | a second delegation over the same subtree (co-equal), made by the system owner or by the data owner when allowed to pass on |
| Users | use the system | memberships of the building's groups, ending by themselves |
| Security officer | the second key where the class asks for one | the officer, named approvers, managers through another chain (0008) |

Already enforced: nobody adds themselves; an elevated or privileged group needs a second key from outside the actor's
chain; memberships have an end within the delegation's maximum; a delegation cannot outlive or exceed its parent; the
reconciler writes the result to the identity broker, which the camera system reads (OIDC group claims, SCIM or LDAP).

A typical tree:
```
camera                      (system owner: subgroups, delegate; max class elevated)
  camera/building-a         (data owner A + deputy A: members)
    camera/building-a/view      carries camera-view@building-a       (low)
    camera/building-a/export    carries camera-export@building-a     (elevated: a second key)
  camera/building-b         (data owner B + deputy B)
```

## Gaps and extensions
- **G1 The system owner's envelope.** Per entitlement, set once by its owner and decided by Rego on every membership:
  which populations may hold it (staff only, never externals or agents), which checked claims a member needs (for
  cameras: an employee of the organisation, a privacy briefing no older than a year), the longest membership, the most
  members per building. The system owner is not asked per person; the envelope is checked for every person.
- **G2 Never one manager alone (continuity).** A rule that every subtree with a members power has at least two active
  managers. Below that: a warning to the system owner and the data owner, a next step that names who can appoint the
  deputy, and retiring the last-but-one manager asks for a replacement first. Configurable minimum, default 2.
- **G3 Handing over while away.** Co-equal deputies cover most of it. Optionally, an acting delegation that starts at
  a date or when the data owner marks absence, and ends on return, with the data owner told what was done meanwhile.
- **G4 "Validated and trusted" on the record.** Adding a member records why (need to know) and which claims were
  checked; the claims come from the one checker contract of 0009 section 3 (a person, an HR source, a training
  register), so the validation is evidence, not a promise.
- **G5 Periodic review.** The data owner and deputy get a review of their building's members every `review_days` for
  the class (the setting exists): keep, end, or let it lapse; the system owner sees only whether reviews happen.
- **G6 Joiners, movers and leavers.** A leaver's memberships end at once (from the HR source). A mover to another
  building is flagged to the old building's data owner, who keeps or ends the access; it is not ended silently, and
  not kept silently.
- **G7 What the system owner sees.** By default no names: per building the number of members, managers, last review,
  envelope breaches and lapsed claims. Names only with a stated reason, logged, decided by the view policy. A switch
  to suspend one building's access at once (an incident) without seeing who is in it.
- **G8 The system's own roles.** View, export, pan-tilt-zoom control and administration are separate entitlements
  with their own classes; export and administration ask a second key. KeyClerk tells the camera system who holds
  which; the camera system enforces and logs every view.
- **G9 Privacy and the law.** Watching camera images is processing of personal data with a purpose and, in Belgium,
  rules of the camera law on who may view. The building's groups are the list of people allowed to view, always
  current and exportable for the controller and the data protection officer, with the reason of each membership.
- **G10 Urgent access for hours.** An investigator or the police need to see one building's images now: a
  membership in hours (0010 section 2) with a second key, ending by itself, shown in the review.
- **G11 The same pattern elsewhere.** Doors per building (physical access), file shares per team, roles in a
  business application, a fleet of devices: a system owner sets the envelope, data owners decide the people, deputies
  cover. The model is the same; only the entitlements differ.

## Harder: half the viewers work for contracted security firms
The organisation has several sites. Security company A watches half of them, security company B the other half. Their
people have no account on the internal network. B can federate identity (its own identity provider, phishing-resistant
sign-in); A cannot yet.

### What changes, and what stays
- The building's data owner still decides who watches building A's cameras, inside the system owner's envelope. The
  people are now partly external, and their organisation is a counterpart with its own trust (the federation link of
  the trust-federation decisions D1 to D10, and FTEF's person-binding proposal).
- **Company B (federated):** a federation link to B's identity provider, scoped to the tenant and to the sites B
  watches. Per kind of claim (D4): B's sign-in and its multi-factor are accepted, B's statement that a person works for
  B is accepted, nothing else (no group or role from B ever becomes a right here). A person of B gets a person record
  bound to that link on their first sign-in; their memberships still come from our data owners. A leaver at B cannot
  sign in from that moment (B disables them), and B's roster or SCIM feed ends their memberships here too.
- **Company A (not federated):** the same people need accounts in our own broker: guest accounts with passkeys, issued
  through the invitation flow (0010 section 5): our contract manager or the data owner invites A's people by name, each
  registers with a passkey and is identity-checked once (an ID document at the front office, or a remote check). A's
  leavers are only known if A tells us, so: a contractual leaver duty, a short lease (the contractor lease), the
  sponsor's monthly confirmation (already in the access lifecycle), and the kill switch per organisation.
- **Different trust, different envelope.** The camera system owner's envelope reads the partner's band per kind of
  claim: B (federated, evidence on file) may view from anywhere the system allows; A (lower band, local accounts) views
  only from the monitoring room's managed devices, never exports. Both are configuration and Rego, with these as the
  shipped defaults.
- **Which firm watches which site** is a fact on the record: the link names the places it covers. A person of A can be
  added to building 4's cameras only if A covers building 4.

### New gaps
- **G12 Delegations limited to a population.** A delegation that may only add people of one organisation (for
  example, the security contract manager adds A's people across A's sites, and nobody else).
- **G13 Delegated administration to the partner itself.** B's team lead manages B's own people inside our envelope
  (adds and removes B's people on the sites B covers, never anyone else, never above B's band), so our data owners do
  not have to track B's rota. For A the same role stays with our contract manager until A can federate.
- **G14 Person records for federated people.** A person of a federated partner is created on first sign-in, bound to
  the link and its issuer, and ends with the link or B's leaver signal; the engine checks that the claimed
  organisation is the link's.
- **G15 Local accounts for a firm that cannot federate.** Invitation, passkey, a one-time identity check, a short lease,
  monthly sponsor confirmation, a leaver duty in the contract; moving A to federation later keeps the person and swaps
  the account (the persona graph shows both).
- **G16 Contract end ends everything.** Ending the contract (the link) ends every membership, lease and session of that
  firm's people at once; renewing the contract does not bring them back by itself.
- **G17 Coverage and rota.** Which firm covers which site, for which period (a change of contractor on a site is a
  dated event); a person of the old firm loses that site the day the new firm starts.
- **G18 Never two places at once.** A guard of A on duty at site 1 who signs in to the cameras of site 5 (not A's) is
  refused by coverage; one signing in at two sites at the same moment is flagged.

### Order, with the contractors
G1 and G2 first, then G12 and G16 (they keep the firms inside their sites and their contract), then G13 and G14 with the
federation link, then G15.

## Order proposed
G1 and G2 first (they make the story safe), then G7 (what the system owner sees and the building switch), G5 and G6
(keeping it true over time), G4 with the claims slice, G10 with access in hours. G3, G8 and G9 are mostly
configuration and text on top.
