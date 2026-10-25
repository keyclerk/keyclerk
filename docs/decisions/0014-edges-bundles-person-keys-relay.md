# 0014: Edges - signed bundles, ceilings, visit leases, person keys, the relay, escrow and evidence

- Status: accepted (2026-10-23): build everything an edge implementation needs to continue. The requirements come
  from that edge's own design (its trust model, its hardening and its offline evidence) and from its interface
  contracts: lease credentials, signed lease bundles, pre-staged and carried visit leases, a break-glass credential, a
  per-edge ceiling and recording backfill.
- Date: 2026-10-23
- Builds 0013 D3 (a child pulls signed, serial-numbered bundles) for one kind of child: an edge, a small site appliance
  that enforces leases on a bastion while it may be cut off. KeyClerk stays a governance engine: it decides and signs;
  the edge agent applies, next to the system it guards, with the shared core elsewhere.

## Decision
1. **An edge is a record.** `edges`: id, the edge's enrolment public key (Ed25519, one per edge), its officer (a person of
   the organisation) and the officer's ceiling-signing public key (a hardware key), its hardware profile claim, and its
   targets. Enrolling an edge is a governed change: proposed by the root, completed by the security officer's key. The
   officer is never the root, the security officer or a member of a privileged group: a core administrator cannot
   widen an edge's ceiling.
2. **Edge requests are signed.** The agent signs every request with its enrolment key over method, path, a timestamp, a
   nonce and the body's hash; the desk refuses a wrong signature, a skew above 5 minutes and a replayed nonce. No
   session, no cookie, no bearer token.
3. **Bundles.** Per edge, a JSON document in canonical form (sorted keys, no spaces) signed with the bundle key, which
   is separate from the records key: edge id, serial (one higher on every new bundle for that edge), issue time, the
   horizon per class (privileged 1 hour, elevated 24 hours, low 7 days by default, set in Rego), the leases (person,
   target, role, class, from, until), the visit leases, the revoked lease ids, the ceiling serial and hash it was cut
   against, and the edge policy module (WebAssembly) with its hash. Nothing outside the ceiling enters a bundle. The
   reference verifier (`keyclerk.edge.verify_bundle`) refuses a lower serial, a wrong signer, a time before the newest
   signed time seen, and leases of a class whose horizon has passed; it is the specification an agent conforms to.
4. **The ceiling is signed data, read by signed Rego.** The officer signs a ceiling document (serial, persons or roles,
   targets, the longest lease, the longest offline validity, the lease classes, the hardware profile, the remote-reach
   mode and ports) with their hardware key. KeyClerk's shipped `ceiling.rego` decides what it allows, in the core when a
   bundle is cut and in the agent from the same module: core policy narrows, never widens. A ceiling with a lower serial
   or a wrong signature is refused. The edge's design asked for the ceiling "in Rego": the logic is Rego and changes by
   policy; the officer signs data, never code, so no officer-written program runs in the core or the edge.
5. **Visit leases** (`edge_visit_leases`): one edge, one person, the person's SSH public key, named targets, a window of
   their own (default at most 72 hours, set in Rego, never above the ceiling's longest offline validity), on assured
   edges only, the profile taken from the edge's last attestation report, never from configuration. Governed: a second
   key from the security officer or a named approver. A class horizon does not end them; their window does.
6. **The edge policy is one signed artifact.** `edge.rego` (admit a session, a lease's validity at a moment, the offline
   cap, the visit window) compiles to WebAssembly with the other policies; the bundle carries the module and its hash;
   `tests/conformance/edge.json` holds input and expected output pairs that KeyClerk's tests run and an agent runs too.
7. **Person keys** (`person_keys`): at hardware-key enrolment the browser derives an X25519 key pair from the passkey
   through WebAuthn PRF; the public half, the SSH public key the hardware key holds, and the authenticator's facts
   (user verification, attestation format) are registered. Governed: proposed by the person, a second key from the
   security officer or a named approver; one active key per person, unique across persons, user verification required.
   The private half never leaves the browser and is derived again at each use.
8. **The relay.** An edge encrypts a lease credential to a person key (X25519, HKDF-SHA256, AES-256-GCM:
   `keyclerk.relay`); the desk stores only ciphertext and hands it over once, to that person, within 10 minutes of a
   fresh sign-in; the browser decrypts. The desk holds no key that decrypts it; there is no fallback: a person without a
   PRF key receives nothing.
9. **Escrow and break-glass.** An edge sends a new break-glass value as two ciphertexts, one per custodian key; the desk
   keeps them, relays each to its custodian and returns a signed acknowledgement, after which the edge may forget the
   value. A reported use of break-glass opens an incident record that the security officer sees.
10. **Evidence intake.** An edge reports recordings as entries in a hash chain (sequence, previous hash, recording hash,
    size, session, time); the desk checks the chain continues, keeps it, and returns a signed acknowledgement up to a
    sequence, after which the edge may delete its copies.

## Not decided here
The checking signer (decision 0015) will hold the bundle key when it is built; until then the bundle key is a separate
file the desk reads, separate from the records key. Phoned unlock and signed updates of the edge's software are not
KeyClerk's (phoned unlock was taken into KeyClerk by 0014c below).

## Consequences
New record kinds `edges`, `edge_visit_leases`, `person_keys`; new desk actions `enrol_edge`, `set_ceiling`,
`grant_visit_lease`, `enrol_person_key`; edge API routes under `/api/v1/edge/`; person routes for key enrolment and the
relay; policies `edge.rego` and `ceiling.rego`; modules `keyclerk/edge.py` and `keyclerk/relay.py`.

## 0014a. Amendment (2026-10-23): the trust model after the adversarial review
A thorough adversarial review found that the ceiling was enforced only by the core it is meant to constrain, that the root chose the
officer's key, and that the reference verifier missed the edge id and future issue times. Changed:
- **The ceiling travels in the bundle** with the officer's signature. The agent pins the officer's key on site (from the
  officer, never from the desk), checks the signature, keeps its own ceiling floor, and caps every lease's horizon at
  the ceiling's longest offline validity. A bundle with leases and no ceiling is refused.
- **The officer and the edge prove their keys at enrolment**: both sign the `kc-edge-officer-v1` statement (edge,
  enrolment key, officer, officer key); an enrolment key serves one edge.
- **"Never a core administrator" holds at every use**: checked when a ceiling is set and at every bundle cut. When it
  fails, the edge's bundle carries no ceiling and no leases, and an `officer_not_independent` incident is raised.
- **A role (a core group) admits only to low-class leases**; elevated and privileged leases and visit leases need the
  person named in the ceiling (core administrators control group membership).
- **Signed objects are exact bytes**: canonical JSON (no floats) shipped as base64 with the signature over those bytes,
  and every signed object names its format and key id (`kc-edge-bundle-v2`, `kc-edge-escrow-ack-v1`,
  `kc-edge-evidence-ack-v1`, `kc-policy-release-v1`). The request signature binds the edge id (`kc-edge-request-v2`);
  an unknown edge and a bad signature get the same answer.
- **The policy is released separately**: `tools/sign_policy_release.py` signs a manifest of the module hashes with a
  release key kept apart from the bundle key (the deployment holds it offline); the desk ships the manifest from its
  store (`policy-release.json`), and an agent that pins the release key refuses modules it does not name.
- **The bundle key** is created 0600 from the start and only before any edge has pulled; a key that goes missing
  afterwards stops the desk's edge routes until it is restored. `GET /edge-key` returns its key id for an out-of-band
  comparison before pinning.
- **The newest bundle is complete**: lease ids are stable while their grant holds; whatever an edge holds that is not in
  the newest bundle has ended. A visit lease ends when its person's hardware key is ended.
- **Conformance** adds verifier vectors (`tests/conformance/edge.json`, `verifier`): fixed keys, bundles and the
  reference verdicts, for agents in any language.

## 0014b. Amendment (2026-10-23): what an edge agent needs to act
From a gap analysis against the edge's interface contracts. Leases carry the broker username, kept in sync, because
the gateway on the edge signs people in by that name, not by KeyClerk's anchor.
- **A lease names the person as the edge's systems know them**: `username` (the broker's username, which Warpgate's
  OIDC sign-in and the facade use; the reconciler saves anchor to username in its state, `usernames.json`), and the
  holder's active person key (`key_id`, `public_key`) for credentials. A visit lease carries the target's `role`.
- **A session cap per lease**: `edge.rego` sets `session_max_hours` per class (low 8, elevated 4, privileged 1); an edge
  target may set a shorter `max_session_hours`; each lease carries the cap that applies, so the edge can end a session that outlives it.
- **The relay is scoped**: an edge relays a credential only to a holder of a lease in its last bundle, with purpose
  `lease:<id>` equal to the envelope's context; it expires with the lease; at most 10 per edge and person.
- **Nothing is destroyed by a failed open**: taking a relayed ciphertext marks it taken; the browser confirms after it
  opened it with the key the item was sent to, and only then is it deleted.
- **Escrow** goes only to the edge's designated custodians (`custodians`, at least two people, set at enrolment), both
  halves or none; the halves are kept until each custodian confirms; `GET /edge/escrow/{item}` returns a sealed status
  (`kc-edge-escrow-status-v1`), and the edge forgets the value only when it says `confirmed`.
- **Retries are safe**: `GET /edge/bundle?serial=N` returns the same sealed bundle for the serial already cut; an
  evidence resend after a lost acknowledgement is no change, and `GET /edge/evidence` returns the head.
- **A fresh sign-in is fresh**: `/login?fresh=1` asks the broker for a new authentication (prompt=login, max_age=0); the
  session keeps the broker's `auth_time`, and a secret is handed over only to a browser session within 10 minutes of it.
- **Attestation is claimed** until quotes are verified (`attestation_verified: false`), and a change of the claimed
  profile raises `attestation_changed`.

## 0014c. Amendment (2026-10-23): carried leases, phoned unlock and the edge lifecycle
Phoned unlock lives in KeyClerk, because who may approve an unlock and the record of every unlock are governance, not
enforcement; this part is built before a pilot.
- **Carried visit leases** (`kc-edge-carried-v1`): issued to the person after a fresh sign-in, at most
  `carried_max_hours` inside the visit lease, with a serial per edge and person; `verify_carried` is the reference.
- **Phoned unlock**: an X25519 unlock key per edge and one for the desk, a secret derived on both sides, a 10-character
  HMAC code read by an unlock approver who is never the person, limits in edge.rego, a log line and an incident each.
- **Rotation** (`edge_rotations`): a new enrolment key or officer, signed by both, the security officer's key; the
  edge's current keys are the newest rotation in force.
- **Ended edges** get a sealed `kc-edge-ended-v1` with 410; **silence** past `pull_max_hours` raises `edge_silent`.
- **Incidents** are capped at 60 an hour per edge, kept to the newest 5000, and closed by the officer or the security
  officer; an evidence chain break raises `evidence_fork` once per head.
- **An SSH key belongs to one person.**
- **Ending an edge, a person key or a visit lease** is an administrative revocation the engine now accepts (before this,
  `end_edge_record` was refused as an unknown id).
- **Desk forms**: grant and end visit leases, read an unlock code, close incidents, paste a prepared enrolment or
  rotation; the hardware key page carries visit leases.

## 0014d. Amendment (2026-10-23, accepted 2026-10-24): one signing mode, sealed objects everywhere
- Status: accepted (2026-10-23, choices E1 sealed everywhere and E2 one cut-over on a tag; confirmed by the edge
  implementation). Built in 0.23.0. The problem was found while porting the verifier to Go.
- **Problem.** Sealed objects are verified over their exact bytes, but the officer's ceiling and the enrolment
  statement are verified over `canonical(parsed document)`: every verifier must reproduce Python's `json.dumps`
  byte for byte. RFC 8785 canonicalisers (Go's jsontext.Canonicalize, JavaScript ones) differ on name order for
  non-ASCII keys and on large integers, so a correct port can still disagree on a signature.
- **Proposal.** The ceiling becomes a sealed object the officer signs (`{bytes, signature, key, key_id}`, format
  `kc-edge-ceiling-v2`), carried as is in the bundle; the enrolment and rotation statements likewise
  (`kc-edge-officer-v2`, signed by the officer and by the edge over the same bytes). Verifiers then only check
  signatures over bytes and parse JSON; no verifier canonicalises anything.
- **Cost.** A wire change for the edge agent and the officer's signing tool (`edge_cli ceiling`/`statement` emit
  sealed objects); existing ceilings are re-signed once by each officer. A transition window where the desk accepts
  both forms, or a cut-over on a tag both sides pin.
- **Alternative.** Keep both modes and pin the canonical form to RFC 8785 exactly, with conformance vectors for the
  edge cases; cheaper now, but every new language port repeats the risk.
- **As built (0.23.0).** The ceiling is a sealed `kc-edge-ceiling-v2` the bundle carries as sealed; the statement is
  multi-signed (`{bytes, signatures}`, `kc-edge-officer-v2`, purpose `enrolment` or `rotation`) by the officer and each
  node, and lists the nodes (`{enrolment_key, unlock_key, tpm}`, one or two: ready for a high-availability pair, as the adversarial review of
  2026-10-24 asked) so
  it needs no v3 for the HA profile; the unlock key is now inside what the officer and the edge sign. The engine checks
  the signatures over the bytes and that the statement says exactly what the record holds. v1 dropped without a
  migration (no edge deployed); the bundle becomes `kc-edge-bundle-v3`. In the same cut:
  - **Modules by hash:** the bundle names its policy modules by sha256 only and an agent fetches them by
    `GET /edge/module/{sha256}`; the adversarial review of 2026-10-24 found that inlined they made every pull about
    520 KB.
  - **kc-unlock-v2:** phoned unlock over P-256 so a node's key can live in its TPM (TPMs offer P-256, not X25519); the derivation binds
    the edge, the node and both public keys; kc-unlock-v1 (X25519) removed.
  - **Ended notice v2:** `kc-edge-ended-v2` names the enrolment key ids it ends, because a review of the edge agent
    found that a captured ended notice could otherwise end a later enrolment of the same edge; the records checks
    refuse an edge id that was ended before (the desk already refused an existing id).
