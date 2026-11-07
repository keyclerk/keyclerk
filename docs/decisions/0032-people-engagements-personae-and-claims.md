# 0032. People, engagements, personae and claims: proof as a lease on trust

- Status: proposed (2026-11-05), after its specifications, the prior-art and framework review, two adversarial reviews and the
  operator's decision round. Accepted once the edge implementation and the platform model adopt it by their own decisions.
- Scope: one model for KeyClerk, the edge, the platform model and the operator's own offers, so they read the
  same terms. Each project adopts it through its own decision record.

## Context
The operator asked for a model of how real people tie to digital personae, and of proof as a temporary lease on trust,
before anything in the lifecycle brainstorm (docs/reviews/2026-11-05-lifecycle-feature-brainstorm.md) or the external
evidence deep dive (docs/reviews/2026-11-05-external-evidence-deep-dive.md) is built. The edge implementation, platform model and business
sessions said what their projects hold, where the first idea conflicted and which invariants they need (appendix A).
Four adversaries then attacked the first draft: privacy and linkability (LINDDUN), evidence and claims (STRIDE),
offline, time and edges, and lifecycle and organisational abuse. Their 48 findings and where each is answered are in
appendix B; this revision answers every one.

What exists today:
- KeyClerk: a person record (kind tenant, external, agent, workload; unit; personas `daily` and `admin`; owner and
  director for agents and workloads, 0011); a random internal anchor per person in the log, the identity provider's id
  outside it (0028); external sign-in bindings (0024, planned); leases in hours; visits (0009, 0010); approvals as the
  approver's own sign-in (0006, 0015); and **a claim contract already** (0009 section 3): `claim_id`, `subject`,
  `type` from a catalogue, `method`, `level`, `checked_at`, `valid_until`, `recheck_after`, `result`; the policy names
  which claims an access requires; access waits until they hold and stops when one expires; a checker never checks
  their own claim. This model builds on that contract and keeps every field of it.
- The platform model: a person is a principal in a source, a persona an account per plane; decisions key on
  (issuer, subject) and never on token roles; attributes bound to an authority with an assurance level and a freshness
  limit; grants as signed policy data judged locally; only the home revokes globally, any isolated site reduces locally; a
  7-day isolation horizon (a platform-model decision).
- the edge implementation: an opaque person id in every lease; a persona is a marked bastion account; a lease ends at the earliest of
  its own end and its class horizon; an officer-signed ceiling that only narrows; trusted time from the wall clock and
  the boot clock since the last verified bundle, and no lease live after a reboot until a fresh bundle verifies
  (agent/internal/clock/clock.go, agent/internal/agent/agent.go).
- Business session: subjects person, workload, device, infrastructure, agent; a stale attribute is absent, never its last value;
  delegation is the intersection over the actor chain, depth at most 2; proofing records the fact and date, never the
  content; a sponsor is a person in the same tenant.

## The model

### Subjects and homes
1. **A person is a real human known inside one home** (a tenant, a deployment, an isolated site's home) by an anchor: a random
   internal id (0028). There is no global person id.
2. **Every identifier a home stores or sends is pairwise per home.** The subject a home keeps for a persona is the
   broker's pairwise subject for that home; the upstream provider's subject lives only in the erasable mapping (0028).
   An identifier derived from a national register (a Belgian eID sign-in through FAS or CSAM, for one) is swapped for
   a pairwise id at the broker and never stored. Edges receive the anchor only. Two homes that must recognise the same
   person compare a keyed hash of a verified fact under a key held for that scope alone, never a raw id (P4, P5).
3. **At most one person per verified fact in a home:** two person records whose keyed fact hash matches are one case to
   resolve by two people, never two people (L11).
4. **A person record exists only through an engagement**, or within its retention after the last one. Prospects,
   measured domains and other organisation-level facts never create a person. After retention, a **tombstone** stays
   apart from the person record: the anchor and its accounts record (0028), so the person's past signatures still
   verify, holding nothing else. Erasure waits until everything the person owns, sponsors or holds in custody has a
   successor (L12).
5. **An organisation** is a subject of its own (a tenant, a connected organisation, a vendor) with claims of its own:
   its registration, its contract end, a domain it holds, its social and tax debt status. An organisation that is a
   natural person (a sole trader) is marked `natural_person` and falls under every person rule; its company number is
   kept as a salted reference only (P8, L9).
6. **Workloads and agents** have an owner, and agents a director. An agent's rights lie within the intersection over its
   director, its director's owner and its own owner; the actor chain is recorded, at most 2 deep; no irreversible
   action. A personal assistant's director is a person; changing a director is a governed change (L8, platform 7,
   business I4).
7. **Accounts that are no one's persona** exist by design: sealed break-glass accounts, an edge agent acting for its
   site, accounts found unmanaged. Each carries a class, an accountable owner who holds an active engagement, and for
   an unmanaged account a deadline by which its system's owner adopts or removes it (G7). The owner leaving opens a
   review; a break-glass custodian leaving starts the rotation of what they held (L7). Accounts that 0028 calls
   "owners, approvers and contacts without a person record" are resolved by this model: an approver resolves to a
   person with an active engagement at the moment of signing, or the approval does not count.

### Engagements
8. **An engagement** is a person's relationship with an organisation over a time: a kind (employee, contractor, partner
   staff, visitor), a source (an HR feed, a vendor management system, a sponsor's invitation, a signed people
   register), a sponsor, a start and an end, and a state (proposed, active, suspended, ended). Owning an agent or a
   workload is not an engagement but a duty that hangs off one; when that engagement ends the duty passes to a named
   successor or what is owned is suspended (L1).
9. **The sponsor** is a person of the same tenant holding an active engagement of a kind the tenant allows to sponsor;
   externals and visitors never sponsor. A sponsor's authority rests on an active engagement of their own that nobody
   sponsors, so a sponsor leaving never leaves a chain behind; mutual sponsorship between two people is a finding; no
   one sponsors or coordinates an engagement on themselves or on an organisation they own. The sponsor's own engagement end is a bound on what they
   sponsor (point 23). A sponsor re-attests every N days; no answer ends what they sponsor. When the sponsor moves,
   what they sponsor goes to review; when they leave, it ends unless reassigned in time (L3, L9, business).
10. **Externals and partner staff enter only through an engagement** with a sponsor and an end. A visit is an
    engagement of kind visitor; visits above a threshold force a contractor engagement (L4, 0009, 0010).
11. **A grant names one engagement for its whole life;** it never moves to another. Rehire and conversion are a new
    engagement on the same person, never a second person; grants do not carry over; claims issued by the old
    engagement's organisation end with it; person-level proofing survives only once reconfirmed (L5).
12. **Leaving is per person, not only per engagement.** An admin persona is held under exactly one engagement. A
    for-cause end of any engagement suspends every engagement of that person, and a for-cause marker outlives the
    engagement under its own lawful basis and period. A persona's subject disappearing at its source suspends the
    person and opens a leaver case; an engagement's end is the earlier of its source's end and that disappearance.
    Removals apply at once; only additions wait as proposals (L2, L5, L6).
13. **Clocks run per person,** not per engagement: review and dormancy clocks, caps on total time and on privileged
    hours, per person and per (person, entitlement), running on across any gap between engagements shorter than N
    days, and counted per sponsor and organisation against the caps (L4).
14. **Approvers see a person's grants across all engagements** (G3), so a sponsor never judges only their own slice (L2).

### Personae
15. **A persona is one account of one person, for one plane** (daily, admin), keyed by the home's pairwise (issuer,
    subject); an e-mail address is a contact attribute, never the key (the edge implementation's decision 0010 point 4 moves to this through
    the edge implementation's own decision, once Warpgate matches by subject).
16. **One person per account per edge**: two persons under one bastion username means neither gets it (an earlier finding of the edge implementation).
17. **The identity provider authenticates and never grants.** Decisions key on grant data for (issuer, subject), never
    on a role or group claim in a token (platform 2, the edge implementation).

### Claims: proof as a lease on trust
18. **A claim is 0009's claim contract**, extended: a registered type, the subject (a person, an organisation, a
    persona, a workload), the issuer, two rungs (that the evidence is genuine, that the presenter is its holder) and the
    level that is the weaker of them, `valid_from`, `valid_until`, `recheck_after`, the revocation route, the purpose
    and scope it was collected for, the lawful basis, a pointer to the evidence, and the checker's decision as a proof
    (0006). Never the document, a photo or a biometric template.
19. **In the signed log a claim and an engagement are an id and a digest only.** Their attributes (type, issuer, level,
    dates, purpose, sponsor, the evidence pointer) live in an erasable side table beside the log, as 0028 keeps approval
    tokens, so erasing a person leaves no quasi-identifying history behind. The evidence pointer is salted per claim
    with a random salt kept in that table, never derived from a national register number or a document number, and
    under a key apart from the cross-home key (P1, P3, P9).
20. **The claim type registry** holds, per type: its authority, its longest validity, its retention class, its lawful
    basis (never consent for employee or contractor types), its revocation route pinned with its endpoint and key, its
    maximum status age, its maximum offline reliance, the channels allowed and the lowest rungs. A type whose mere
    existence reveals special-category or criminal-record data is refused: such a fact enters only as a neutral
    capability ("fit for work at height in zone B", "cleared to level 2"), its basis kept off the log. Registering or
    changing a type is a high-risk change with a second key (0008, 0015) (P2, P7, P9, P11, F7, F9).
21. **The level is computed, never typed.** The intake channel stamps the method, and only it can; each rung is the
    channel's ceiling for that rung from the registry's table. A register lookup or a signed PDF has a holder rung of
    none unless it is matched to the person's proofing. A presentation is bound by a nonce to (home, anchor, engagement,
    claim type), as 0006 binds approvals. A document number's keyed hash showing up on a second subject in one home is
    an alert (F3, F4).
22. **Creating a claim or raising its level is a widening** and high risk under 0015 D2: the checker's proof plus the
    signer's check. Ending or lowering a claim is low risk. In policy a claim appears only as a requirement joined to a
    grant, never in a disjunction and never as a substitute for a grant; a lint holds this (F2).
23. **A claim is valid only inside its effective window,** whose end is the earliest of: its `valid_until` (the earliest
    of a verified expiry, the type's longest validity and its recheck interval; a date printed on a scan is unverified),
    its issuer's trust end on the allowlist, its last status fetch plus the type's maximum status age, and its
    organisation's bounds. Outside it the claim is absent, never its last value: what rests on it is denied at once,
    and the review that opens may restore, never keep access alive while it runs (F6, F9, L10, business).
24. **Negatives dominate.** For one subject and type within a window, a fail, a revocation or an issuer's revocation
    outweighs any pass; a pass after a fail needs a second checker who sees the fail. Revoked never returns: a renewal
    is a new claim that names its predecessor, and a renewal of a predecessor revoked at or before its issue is void.
    Revocations merge as a union (F10, T3, platform 3).
25. **Separation of roles.** For an engagement and the grants resting on it, the sponsor, each checker and the approver
    are different persons, counted per person across personae and engagements; the subject is none of them; a checker
    is not in the sponsor's reporting line; no one approves for a deputy they appointed; mutual approvals are findings
    (F1, L9).
26. **Checkers are checked.** A second checker re-checks a random sample blind to the first verdict; each checker's pass
    rate and time per decision are kept; seeded canaries test them; similar templates are flagged inside the intake
    (F5).
27. **Intake is a separate, sandboxed process without network.** It hashes what arrives before parsing it; the checker
    sees only the re-encoded raster and that raster's hash enters the checker's nonce, so a desk cannot show one image
    and record another (F8).
28. **Revocation routes never watch the person.** Only whole-list status mechanisms (Bitstring Status List, Token Status
    List) fetched and cached as a whole; a per-credential query to the issuer only for organisation claims. A route
    taken from the presented document is never followed (F7, P7).
29. **Reuse stays within purpose.** A claim serves another grant only within the purpose and scope it was collected for;
    outside them a compatibility rule or a fresh presentation by the person (P10).

### What rests on what, and the fold
30. **A grant or lease rests on one engagement and on claims**, named in it. Its effective end is the earliest of: its
    own end; its engagement's end; its sponsor's engagement end; every claim's effective end (point 23); each claim's
    last status check plus its maximum offline reliance; the organisation's bounds; the edge's class horizon; and the
    isolation horizon. When a claim's status cannot be fetched at the desk, that bound is now (F12, T4, L3, L10).
31. **The desk folds that earliest end into the signed time it sends.** An edge enforces it with the time rules it
    already has; the fold is the whole interface (the edge implementation's preference). The edge receives only a coarse reason from a
    closed set (`lease_end`, `horizon`, `bound`); which bound it was stays on the desk (P6, T8).
32. **The checking signer recomputes the fold from the records** before it signs (0015), and the bundle carries a hash of
    the bound set, so a wrong fold by a taken-over desk is refused and auditable (T9).
33. **Claims only narrow what an edge holds;** they widen nothing past the grant and the officer's ceiling. Effective
    rights are the intersection over the claims a grant rests on and over the actor chain (the edge implementation, business I2).
34. **A desk restored from backup never lengthens what an edge holds.** Edges keep revocation tombstones and a per-lease
    end floor and echo them; a restored desk takes their union and fetches the status lists again before it serves
    (T2, 0019).

### Time and offline
35. **One trusted-time rule** for every edge and isolated site: the later of the wall clock and the wall clock at the last
    verified signed object (the trusted time recorded then, never the raw wall clock) plus the boot clock since it;
    after a reboot while cut off, nothing is live (or only
    reductions apply) until a fresh signed time arrives from the desk, a relay or the site witness. This is the rule
    the edge implementation's agent already implements; the edge protocol text states only the weaker "later of the clock and the
    newest signed time", which a frozen clock defeats; edge protocol 1.5 states the rule (section 1) with the
    conformance family `trusted_time` (2026-11-05). The platform model's simulation of a cut-off site then found that a boot clock
    frozen while the wall clock is honest (a paused virtual machine), then thawed, then the wall clock set back, still
    left the trusted time a day behind; so at every wake, at most an hour apart, the edge records a new anchor, the
    later raw reading (never the skew-tolerant trusted time, which ClaimLease showed lets the lag grow by the skew at
    each wake). One clock tampered at a time is the deployment's assumption; both at once is its stated limit. Edge
    protocol 1.5 section 1 states it, with the conformance family `ratchet`; ClaimLease checks it (variants NoRatchet,
    RatchetTrusted, BothClocks), the correct model at small bounds over 326,050 states in TLC and Python alike. At the full
    bounds of `ClaimLease.cfg` (MaxT = 5) TLC explored 93,951,702 distinct states of the ratchet model with no violation,
    28,027,701 still on its queue, before the run was stopped for memory (2026-11-05): not a completed check. A rule taking the
    earlier of the clocks may serve to refuse widening, never to decide an end (T1).
36. **The desk's issue time never goes back** and comes from the signer or the witness; a site counts as reached only
    once it echoes the serial or confirms removals, and a lagging echo is an incident (T7).
37. **Absolute times only:** RFC 3339 with an offset, or epoch seconds; a date-only validity becomes the start of that
    day at UTC+14, its earliest reading (T10).
38. **An end in time reaches every site; a revocation takes effect at a site only once the site confirms it.** Until
    then the exposure is the folded end, bounded by the claim's maximum offline reliance and the isolation horizon, and
    unbounded where the edge's time cannot be trusted. The officer gets an incident per unconfirmed site with each lease
    and its remaining end; the person is told that access ended and that further use is logged as unauthorised (T12,
    the edge implementation conflict 4, business I3).
39. **Revocations travel by every channel there is:** the bundle, the relay's tightenings (0027), and an officer-signed
    tightening carried by hand to a site that never reconnects; a "suspend this claim type" kill folds every bound on
    that type to now; a silent site gets the officer's review of each exposed lease (T11).
40. **Only the home of the subject or scope revokes globally;** any site reduces at once, offline too, and a local
    reduction keys on (subject, grant), holding until the home confirms (platform 4, T3).
41. **Two nodes of an edge share their floors.** Before a node takes over it syncs, from its peer or the local witness,
    the highest serial, the newest signed time, the carried floors and the tombstones; if it cannot, it applies
    reductions only (T5, 0031).
42. **A cut-off site accepts no new proof, with one exception:** a carried visit lease (0014), capped at the last
    bundle's visit lease end and fold; the person is told that a shortened carried lease is void (T6, platform).

### People's rights
43. **The person sees** their engagements, the claims their access rests on, and when each lapses; they get the notice of
    GDPR articles 13 and 14 at the invitation (P11).
44. **No cause in the log:** a state change records that it happened, never why, and every automatic denial opens the
    review in which a person decides (P12).
45. **Retention per claim type:** a claim's attributes go with its engagement plus the type's retention class; the fact
    and date stay in the tombstone's history; a dispute or legal-hold class keeps the document encrypted under escrowed
    keys for types that need it, and the hash key lives as long as the claim (F11, business I5).

### The same pattern beyond people (scoped out for now)
46. Organisations' digital assets take the same shape: a domain holder (validity the renewal date; revocation the
    deletion, then the registry's quarantine), a trademark holder, a mailbox owner (the operator's domain retirement, estate
    file and sale-ready offers). Named so the vocabulary fits; modelled later.

## Amendments from the framework review and the operator (2026-11-05, to fold into the points above)
The framework review (docs/reviews/2026-11-05-0032-framework-review.md) and the operator's note that people are not the
only subjects change the model as below. Before the record is proposed these are folded into the numbered points; until
then they take precedence where they differ.

### Every kind of subject, not only people (operator)
A1. **The model covers every subject kind the estate has:** person, workload (a service, a job, a SPIFFE identity),
    agent (acting for a person or workload), device (an edge node, a sensor, a workstation, a machine with a TPM) and
    infrastructure (a host, a cluster, a network element). ISO/IEC 24760-1's entity covers all of them; NIST SP 800-63-4
    covers people, so people get its levels and the others get their own (point A6).
A2. **Every subject has a home, an anchor that is never reassigned, and a lifecycle** (point A8). The person-only rules
    are the privacy rules (points 2, 19, 20, 43 to 45, N12, N13) and those about engagements; they also cover an
    organisation that is a natural person (point 5).
A3. **A subject that is not a person has a commission instead of an engagement:** its purpose, the person accountable
    for it (an owner duty on that person's engagement, point 8), a start and an end. No commission, no subject: a
    workload, agent or device whose owner's engagement ended passes to a named successor within N days or is suspended
    (OWASP's Non-Human Identities Top 10 ranks improper offboarding first). This generalises points 6 and 7.
A4. **Claims about machines are claims like any other,** with the same two axes: a TPM attestation (0016) or a
    measured boot state, a workload's SVID or its build provenance, a sensor's calibration certificate, a device's
    patch level. Their validity is short and their evidence is technical; they fold into the leases they support
    exactly as point 30 says, so an edge whose attestation lapses loses what rests on it, offline too.
A5. **Credentials of machines rotate on the subject's lifecycle,** not on a person's: a commission's end retires the
    workload's keys and tokens, and a device's decommission retires its enrolment key (0014) and its attestation key.
    Secrets a person knew are point A9 of the brainstorm; secrets a machine holds are retired with the machine.
A6. **Levels per kind:** people on NIST IAL and AAL (and FAL for federation); devices on the attestation profile
    (assured, basic: 0016) and the evidence behind it; workloads on how their identity is issued (SPIFFE attestation,
    a pinned key, a shared secret refused). Each grant and claim type names the level it needs per kind.
A7. **Sensors and other machines that report about people** (a badge reader, a camera, the edge implementation as a trust sensor) are
    subjects in their own right and also issuers of observations about people: those observations are claims with the
    sensor as authority, its own level capping theirs, and every privacy rule of the person applies to them.

### Lifecycle and the person's rights (ISO/IEC 24760-1, NIST SP 800-63A)
A8. **Every subject has a lifecycle state of its own,** apart from its engagements or commissions: established,
    active, suspended, archived, with the transitions suspend, reactivate, archive and erase (ISO/IEC 24760-1 7.2).
    Suspension is reversible; archive keeps only what audit needs (the tombstone of point 4 is the archived state);
    erase removes the rest. A subject's anchor is never reassigned, even after its archived record is erased.
A9. **Causes of suspension or end** include a compromise (every lease on the affected persona or key folds to now, as
    NIST SP 800-63B requires an authenticator to be invalidated at once), a death or a legal order notified by an
    authoritative source, a policy violation and inactivity (the dormancy clock, point 13). The log records that the
    change happened, never why (point 44).
A10. **The person is told** at every suspension or end how access can come back and how to complain (NIST SP
    800-63A), in the closed set of reasons, not the cause.
A11. **Erasure has a deadline.** Point 4's wait for successors is bounded: past the deadline a named default successor
    (the sponsor's line, the tenant's owner) takes over what is still unassigned, and erasure proceeds.
A12. **Proofing is a record of its own** per person, kept in the erasable side table: the steps, the evidence type and
    its authority, and the highest identity assurance level reached (NIST SP 800-63A). A sponsor holds proofing at or
    above the level of what they sponsor (point 9), as NIST requires of an applicant reference.
A13. **Archiving a subject reaches every account downstream:** every persona's plane and every edge (NIST SP 800-63C
    3.10). Whether the keyed fact hash that recognises a returning person survives archiving is a retention class of
    its own (re-enrolment), or it is dropped.
A14. **A change of a core attribute is validated** (a contact address, a source attribute), and a change of e-mail
    address is a binding event (ISO/IEC 24760-1 8.2, NIST SP 800-63A).

### Credentials, status and the wallet (W3C VC 2.0, status lists, OpenID4VP, eIDAS 2)
A15. **The holder axis has two parts:** key-bound (the presentation's key proof checked against the credential's key)
    and person-matched (to the person's identity data or proofing). A credential without a key binding caps the holder
    axis at none (point 21).
A16. **A presentation nonce is fresh and random;** the binding to (home, anchor, engagement, claim type) of point 21 is
    kept in the verifier's state under that nonce, and the audience is checked.
A17. **The status reference inside a credential is followed only under the endpoint pinned for its issuer** in the
    registry, its list verified under the pinned key (point 28 as written would have refused every status check).
    The status age is the least of the type's maximum, the list's ttl, its expiry and its validity end. Lists below the
    status list's minimum length are refused or flagged; fetches go through a cache, never per credential.
A18. **Suspended on a status list is not revoked:** a suspension makes the claim absent while it lasts (point 23); only
    a revocation is never coming back (point 24).
A19. **Issuer trust comes from the lists that govern it:** the EU list of trusted entities for PID and public-sector
    attestations, the trusted lists for qualified ones, a rulebook for the rest; the list's next update bounds the trust
    end (point 23).
A20. **KeyClerk is the relying party, not an issuer.** Its claim is a validation record, never a credential it issues;
    each home is the relying party for the wallet, registers the data it asks for per intended use, and the claim type
    registry generates the request and is checked against that registration. A hosted KeyClerk is an intermediary and
    keeps nothing of the transaction's content. Whether to issue portable credentials later is open question Q8.

### Exchange and signals (SCIM, AuthZEN, Shared Signals, FTEF)
A21. **Engagements are their own SCIM resource,** never attributes of a user; a SCIM manager is the reporting line
    point 25 checks, never the sponsor; SCIM ids stay in the erasable mapping; claims never travel as SCIM attributes.
A22. **A source's signals map to point 12:** inactive or deactivate suspends that engagement at once; a delete, an
    unexplained 404 at reconciliation or an account purge is the disappearance; an activation is a proposal. Events
    are received as notices and the resource fetched again before acting; a mass deactivation above a threshold opens
    an incident instead of suspending a whole tenant on one feed (FTEF section 9).
A23. **Decisions over AuthZEN** take the persona's pairwise subject as the subject, the engagement, actor chain,
    trusted time and site in the context, and answer with the folded end; a decision is never reused past it.
A24. **Shared Signals carry no cause:** account-disabled, session-revoked, assurance-level-change (down only) and
    account-purged, with the initiating entity always "policy" and no reason; one stream per receiver with pairwise
    subject identifiers; a burst of for-cause ends is spread so it looks like any other.
A25. **One vocabulary with FTEF:** claim (about a subject) and evidence item (about a domain); band for level, with a
    published mapping from NIST and eIDAS levels; axis for rung (genuineness, holder binding); lease and fold; issuer,
    withdrawn globally by the issuer or home only; freshness and status ttl; towards less trust. A partner's FTEF band
    caps the level of what it vouches for, and external engagements carry FTEF's no-transit.
A26. **ISO/IEC 24760-1's terms where they fit:** reference identifier (the anchor), identity information authority
    (the issuer), verifier (proofing) for the checker, validation and verification for the two axes, archived identity
    for the tombstone; the edition cited (2019 or 2025) to be pinned.

### Pseudonymous people: identification is an option of the model (operator, 2026-11-06)
The operator asked for this from the start: eIDAS 2 lets a wallet user present a pseudonym, and a relying party may not
refuse one where no Union or national law requires the user to be identified (art. 5b(9) as recalled; the wording is
to be verified against the Official Journal before this record is accepted).

A27. **Identification is a property of the engagement kind, not of the model.** Each kind in the registry states
    `identification: required`, with its legal reference (employment and social-security registration, a regulated
    site's access law, a contract term), or `pseudonym_allowed`. Where no law requires identification, a home does not
    refuse a pseudonym. The defaults: required for staff, contractors and every kind that can hold an admin persona or
    a privileged grant; pseudonym allowed for visitors and desk check-ins. A deployment can tighten either. Turning a
    required kind into one that allows pseudonyms needs its legal reference replaced and is a high-risk change with a
    second key (0008, 0015).
A28. **A pseudonymous person is a person like any other:** an anchor, engagements, claims, leases, the same clocks. It
    lacks only an identifying fact. Its point-3 fact is the keyed hash of the pseudonym under the home's own key (the
    wallet's pseudonym for this relying party, a passkey's credential id, or a visitor token the desk issued), so one
    pseudonym is one person in a home.
A29. **Claims attach without identity.** A pseudonymous person can hold attribute claims whose type allows it: an age
    over a threshold, employment by an organisation through an employer attestation, a qualification, a safety
    induction at this site. The holder axis is key-bound only (A15); person-matched is none by construction, so a type
    whose lowest rungs need a person-matched holder refuses a pseudonymous holder.
A30. **What is counted per human needs identification.** One human with two pseudonyms escapes a cap per person, so a
    kind whose safety rests on a count per human (the visitor threshold of point 10, the caps on privileged hours of
    point 13) requires identification. For pseudonymous visitors the threshold counts per pseudonym and per sponsor;
    crossing it asks the visitor to identify, and never identifies them silently.
A31. **Identification is added, never inferred.** A pseudonymous person becomes identified only by presenting
    identifying evidence through an intake channel, a governed change approved like a claim. KeyClerk never links a
    pseudonym to an identity by matching, and never merges two pseudonyms on a guess. An identified person becomes
    pseudonymous again only through erasure.
A32. **No re-identification mapping is held.** For a wallet pseudonym the wallet keeps the secret; for a desk token the
    home keeps only its keyed hash. A home that must identify a pseudonymous person later, after an incident, asks the
    person or uses what the law gives it outside KeyClerk. An edge receives the anchor only, as for anyone (point 2).
    A pseudonymous person's lease carries no e-mail, so the bastion signs them in by key, or by the pseudonym at the
    broker, never by e-mail.
A33. **Exports stay pseudonymous end to end, and a pseudonymisation gateway fits there.** KeyClerk's events (the SIEM
    stream, reports, the governance queries of 0.32.0) carry anchors, never names. A home that pairs KeyClerk with a
    pseudonymisation gateway keeps both standalone and joins them by an adapter, with no shared key and
    no shared runtime: the gateway masks the free-text fields that can still hold a name before anything reaches an
    analysis or an AI session, and its own two-person unmask is the only way back. The constructions are alike (a
    keyed hash under a key held for one scope only, point 2), but the keys are never the same: a KeyClerk fact hash
    and a gateway pseudonym of the same input must not be linkable.

## Invariants (checked by the specifications and tests)
- N1 Identifiers are pairwise per home; no raw cross-home id; cross-home recognition only by keyed hash under a
  scope's own key; at most one person per verified fact in a home.
- N2 No person record without an engagement or its retention, apart from tombstones; no persona without a person,
  except the owned classes of point 7; every approver resolves to a person with an active engagement when signing.
- N3 Decisions key on (issuer, subject) and grant data, never on token roles or groups.
- N4 A lease's effective end is never later than any bound it rests on (point 30), across a desk restore.
- N5 A claim outside its effective window is absent; a revoked claim, and any renewal of it issued after the
  revocation, never returns; negatives dominate.
- N6 Nothing widens offline; under an adversarial clock a lease is never used after real time passes its end plus
  twice the skew (10 minutes with the protocol's 5), unless the edge is in reductions-only mode.
- N7 A claim's level is the weaker of its two rungs and comes from the channel, never from a person.
- N8 An agent never exceeds the intersection over its director, the director's owner and its own owner; the chain is
  at most 2 deep.
- N9 No document, photo, biometric template, national register number or document number in any claim, log or bundle.
- N10 No one approves, checks or sponsors their own grant, claim, persona or engagement, or one for a deputy they
  appointed or an organisation they own.
- N11 Sponsor, checkers and approver of an engagement and its grants are distinct persons; every sponsor holds an
  active engagement of a sponsoring kind that nobody sponsors. (The first draft said "one level deep and never
  cyclic" per person; the Alloy model showed an employee who is also someone's visitor elsewhere breaks that harmlessly,
  so the invariant is stated on the engagement the authority rests on.)
- N12 Everything specific to a person in the log is erasable by anchor: the log holds ids and digests, attributes
  live in the erasable side table.
- N13 No claim type, engagement field or reason code reveals special-category or criminal-record data.
- N14 A grant names one engagement for life; for-cause ended persons hold no active persona; review and dormancy
  clocks never decrease across an engagement change with a short gap.
- N15 Creating a claim, raising its level, and registering or extending a claim type are high-risk changes.
- N16 No engagement of a kind that requires identification belongs to a pseudonymous person; no claim whose type
  needs a person-matched holder belongs to one; no per-human cap is enforced by a count per pseudonym (A27, A29, A30).
- N17 A pseudonymous person becomes identified only through an intake channel's evidence, never by matching; no
  mapping from a pseudonym to an identity is stored (A31, A32).

## How it is modelled and verified
One standard per kind of question, each already used somewhere in the estate:

| Question | Standard | Where it lives | Checks |
|---|---|---|---|
| The terms | ISO/IEC 24760-1 (identity, partial identity, identifier, identity information authority, verifier, relying party), mapped term by term; NIST SP 800-63-4 for levels | this record, a glossary table | a review against the standard's definitions |
| The structure: who may relate to whom | Alloy (relational model, bounded exhaustive check) | `docs/specs/People.als` | today: the rules are consistent and populated, and N11's grounding of sponsors is derived; the other assertions restate rules (second adversarial review M7, M8) and version 2 replaces them |
| The behaviour over time, offline included | TLA+ checked by TLC, with one broken variant per invariant that must fail, as for 0031 | `docs/specs/ClaimLease.tla` | version 2 (2026-11-05): bundles held back and delivered late, the protocol's skew (an end at most 2 S late), reboots and the freshness rule, late status lists, desk restores, the officer's revocation in the signer's log; BoundedExposure, OfficerBounded and NoResurrect hold over 84,108,516 distinct states (before the ratchet, MaxT = 5), nine broken variants each fail; the ratchet model is complete at small bounds only (point 35); still to come: renewals, two nodes, carried leases, two claims (M5, M11, M13) |
| The architecture: components, flows, trust boundaries | FINOS CALM in the platform model's `calm/` | the platform model, by its own work item | the model's gate |
| The controls it satisfies | OSCAL, as the platform model maps controls (NIST SP 800-53 AC-2, PS-4, PS-5, PS-7; ISO/IEC 27002 5.16 to 5.18) | the platform model | the model's gate |
| Privacy threats | LINDDUN on the person, claim and evidence data; STRIDE on evidence intake | appendix B, and the second adversarial review | each threat a finding with a guard |
| What the edge must do | edge protocol conformance vectors for the fold (point 31), the trusted-time rule (point 35), tombstones and end floors (point 34) and two-node floors (point 41) | keyclerk/edge-protocol | the edge implementation's agent passes them |

Broken variants checked (ClaimLease version 2): the 1.4 time rule and no reboot lock (T1), the raw wall clock as the
anchor and any bundle counting as fresh after a reboot (M1), no status-freshness bound (T4), a status list stamped with
the fetch time (M9), a restore that forgets the officer's revocation (M2), a boot clock that pauses and an edge state
rolled back (M3, the deployment's assumptions). Still to write: a renewal that ignores its predecessor's
revocation (T3), a node that takes over without syncing its peer's floors (T5), a carried lease not capped by the last
bundle (T6), a grant moved between engagements (L5), a level taken from the checker (F3), and the Alloy variants
rewritten to weaken one rule each instead of deleting the invariant they test (second adversarial review M8).

## The operator's answers (decision round, 2026-11-05)
- Q1 Engagement is a first-class record; a person exists in KeyClerk only through an engagement or its retention.
- Q2 A lapsed claim (expired, revoked, status unknown) is absent at once: access resting on it ends, and a review opens
  that may restore it, never keeping access alive meanwhile. Against it: an overnight-expired certificate turns a worker
  away; the answer to that is renewal reminders, not grace.
- Q3 A cut-off site never judges new proof. The connected desk judges it and the lease travels: for a crew arriving to
  repair the site's own link, the desk checks each contractor's evidence and issues a carried visit lease (bundle-key
  signed) to their phone or as a QR, which the cut-off edge verifies offline within the officer's ceiling, the horizon
  and the 72-hour cap. Break-glass stays the last resort for a site isolated beyond that.
- Q4 The evidence pointer is a salted hash; the encrypted document is kept only under a dispute class, for the types
  that name one (point 45).
- Q5 Assets as claim subjects: deferred (point 46).
- Q6 This decision is the single home of the model. The platform model and the edge implementation cite it and adopt it by their own
  decisions, without a register copy (no drift; the platform model keeps no machine-readable copy of these terms).
- Q7 Configurable, with defaults: a gap of 30 days keeps an engagement's clocks running; sponsors re-attest every 90
  days; a contractor engagement is required after 5 visits in 90 days; the maximum offline reliance is 24 hours per
  claim type unless the type sets less.
- Q8 Issuing narrow, holder-bound capability credentials is the decided direction, receiving first. The receiving
  channel ("peer credential") comes first: its level is the lowest of the carried source rungs, the home's ceiling for
  the channel and the issuer's FTEF band; the home's own checker, signer and person match still act; a local negative
  outweighs it; it never reaches an edge. It also serves certification bodies, employers and sector issuers. Issuing
  waits for a legal opinion (whether a home issuing to its own contractors is a trust service under eIDAS 2 art. 3(16),
  NIS2 for each home, the GDPR basis) and for attested wallets; an issuer key is never held by a provider on a home's behalf; the safe shape
  and the kill criteria are in docs/reviews/2026-11-05-0032-q8-issuing-adversarial review.md, whose adversarial review recommended "not
  yet" (the operator chose the direction knowing that).
- Q9 The first release covers people and the subject kinds KeyClerk already records: workloads, agents and devices
  (edges, with their TPM attestation as claims), under the commission rule. Infrastructure later.

## Next steps
1. The Alloy and TLA+ specifications of the table above, each with its broken variants, checked. Done for the
   behaviour, version 1 (2026-11-05): `docs/specs/ClaimLease.tla` holds under TLC at MaxT = 5 (2,555,424 distinct
   states) for one lease and one claim with instant delivery and no skew, and its four broken variants (T1 twice, T2,
   T4) each fail; `tools/model_claim_lease.py` explores the same model on every test run. The structure, version 1:
   `docs/specs/People.als` with Alloy 6.2.0 at scope 5 shows the rules consistent and populated and derives N11's
   grounding of sponsors (which corrected point 9); its other assertions restate rules and its broken variants delete
   the invariant they test, so they show little (second adversarial review M7, M8). Version 2 of both is the next step.
2. The prior-art and framework conformance review: ISO/IEC 24760-1, NIST SP 800-63-4, W3C VC Data Model 2.0, eIDAS 2
   and the wallet's architecture, SCIM 2.0, OpenID AuthZEN, FTEF's lease, band and issuer terms.
3. A second adversarial review on what the specifications had to assume.
4. The operator's decision round on Q1 to Q9: done (2026-11-05, answers above); this record is proposed, and the edge implementation, the platform model and the business side each adopt
   it by their own decision. The trusted-time finding (point 35) goes to the edge protocol on its own, sooner.

## Appendix A: the sessions' input (2026-11-05)
- The platform model: invariants 1 to 9 (immutable source anchors, (issuer, subject) at the decision point, revoked never
  returns, global revocation by the home only, nothing past the horizon, weakest wins, agents within their delegator,
  no special categories, no self-approval); wants claim records carried as policy data in the signed bundle, a "rests
  on" link with a deterministic test, a per-site acceptance list, engagements mapped onto its joiner, mover and leaver
  steps, vocabulary aligned with FTEF. Paths: platform/access-lifecycle.yaml, platform/identity.yaml, separation.yaml,
  a platform-model decision, a platform-model decision, a platform-model decision, a platform-model decision, a platform-model decision, a platform-model decision, a platform-model decision, a platform-model decision, a platform-model decision, a platform-model decision
  (the platform model).
- the edge implementation: the edge sees only signed outcomes; every trust bound is a signed absolute time; one person per username;
  claims only narrow; the identity provider never grants; profile gates stay; any change ships as edge protocol
  vectors first; wants the fold, a stable pairwise (provider, subject) per persona, sponsor and engagement on the desk.
  Paths: docs/keyclerk-edge-interface.md, model/edge-decision-interface.yaml, agent/internal/apply/apply.go,
  agent/internal/kcedge/bundle.go, agent/internal/clock/clock.go, decisions 0005 to 0010, 0014, 0018, 0021, 0025
 .
- Business session: invariants I1 to I6 (no person without an engagement, weakest link and intersection, expiry offline and
  revocation failing closed, agents within their delegator, retention with fact and date only, registered claim types
  only); wants a claim schema mapped onto identity.yaml attributes and access-lifecycle grants, the asset pattern of
  point 46, engagements as the only path for externals with FTEF partner evidence on them. Paths: platform/identity.yaml,
  platform/access-lifecycle.yaml, platform/sources-of-truth.yaml, governance/hr-security.yaml, governance/roles.yaml
  (the platform model); the vault's prospecting and .be paper notes.

## Appendix B: the first adversarial review (2026-11-05) and where each finding is answered
| Finding | Severity | Answered in |
|---|---|---|
| P1 the log as a quasi-identifier | critical | 19, N12 |
| P2 special categories in claim types | critical | 20, N13 |
| P3 brute-forceable evidence hashes | high | 19, N9 |
| P4 (issuer, subject) as a global id | high | 2, N1 |
| P5 national register identifiers from the eID | high | 2, N9 |
| P6 reason codes on the edge | high | 31 |
| P7 revocation checks that watch the person | high | 28 |
| P8 sole traders outside the person rules | medium | 5 |
| P9 retention unbounded | medium | 19, 20, 45 |
| P10 reuse outside purpose | medium | 29 |
| P11 consent and transparency | medium | 20, 43 |
| P12 signed disciplinary records, automated denial | low | 44 |
| F1 one person as sponsor, checker and approver | critical | 25, N11 |
| F2 a prerequisite claim is a widening | critical | 22, N15 |
| F3 level inflation by the checker | high | 21, N7 |
| F4 someone else's document, replay | high | 21 |
| F5 rubber-stamp checkers, templates | high | 26 |
| F6 a compromised issuer | high | 23 |
| F7 spoofed registers, lying routes | high | 20, 28 |
| F8 the upload path, view substitution | high | 27 |
| F9 a type with too long a validity | medium | 20, 23 |
| F10 claims that disagree | medium | 24 |
| F11 evidence gone in a dispute | medium | 45 |
| F12 revocation exposure up to the horizon | medium | 30 |
| T1 a frozen clock keeps leases alive offline | critical | 35, N6 |
| T2 a restored desk lengthens ends | high | 34, N4 |
| T3 a renewal escapes its revocation | high | 24, 40, N5 |
| T4 no bound shorter than the horizon | high | 30 |
| T5 two nodes with different floors | high | 41 |
| T6 carried visit leases | high | 42 |
| T7 a skewed desk clock | medium-high | 36 |
| T8 reason codes as a forging guide | medium | 31 |
| T9 the edge cannot check the fold | medium | 32 |
| T10 time zones and dates | medium | 37 |
| T11 mass revocation in DDIL, silent sites | medium | 39 |
| T12 the exposure understated, nobody told | medium | 38 |
| L1 an agent-owner engagement keeps a leaver | high | 8 |
| L2 several engagements, leaving one | high | 12, 14 |
| L3 paper sponsors, chains | high | 9, 30, N11 |
| L4 engagement churn resets clocks | high | 10, 13, N14 |
| L5 rehire and conversion launder access | high | 11, 12, N14 |
| L6 the identity provider deletes first | high | 12 |
| L7 person-less accounts as a back door | high | 7, N2 |
| L8 an agent beyond its person | medium-high | 6, N8 |
| L9 self-approval by proxy, sole traders | medium | 5, 9, 25, N10 |
| L10 a vanished vendor's issuer reused | medium | 5, 23, 30 |
| L11 HR and the vendor system disagree | medium | 3, 12 |
| L12 erasure breaks audit | medium | 4 |

## Changelog
- 2026-11-05 Drafted from the operator's ask and three sessions' input.
- 2026-11-05 Revised after its first adversarial review (48 findings, four adversaries): built on 0009's claim contract; the log
  holds ids and digests; pairwise identifiers; neutral capability types; computed levels; separation of roles; claim
  creation as a widening; negatives dominate; the full fold with status freshness and offline reliance; one trusted-time
  rule; restore, renewal, two-node and carried-lease rules; people's rights.
- 2026-11-05 The trusted-time rule in edge protocol 1.5; ClaimLease checked under TLC with its broken variants.
- 2026-11-05 People.als checked with Alloy; N11 restated on the engagement a sponsor's authority rests on.
- 2026-11-05 Amendments A1 to A26: every kind of subject (operator), lifecycle and rights, credentials and status, exchange
  and signals, from the framework review; the record no longer claims checks the models do not make.
- 2026-11-05 ClaimLease version 2 checked: held bundles, skew, reboots, late status lists, restores; nine broken variants fail.
- 2026-11-05 The ratchet: an anchor recorded at every wake, after the platform model's simulation of a cut-off site.
- 2026-11-05 Proposed: the operator's answers to Q1 to Q9; Q8 after its own adversarial review.
- 2026-11-06 Point 35 and the model table say which TLC runs completed: the ratchet model's full-bounds run did not.
- 2026-11-06 Amendments A27 to A33 and invariants N16, N17: pseudonymous people as an option of the model (operator);
  to be checked in People.als version 2 and in an adversarial review before acceptance.
