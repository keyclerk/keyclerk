# 0028. Personal data in the log: an internal anchor, erasure that reaches every copy, and retention the deployer sets

- Status: accepted (2026-10-25). Points 1, 5 and 7 are built and offered in 0.26.0 (released 2026-10-25), with the
  accounts records and the desk's boundary below; points 2 and 6 with backup in 0.27.0;
  points 3 and 4 in the personal-data release. Amends decision 0022 (point 3 and the restore guard).
- Context: decision 0022 makes a signed, append-only change log the source of truth. A log that can never change is
  at odds with erasure, unless erasure is designed in. For the deployer, the controller, an access history keyed by a
  person's identifier stays pseudonymised personal data while it is kept. Deleting a person's names is minimisation,
  not erasure, so the history still needs a legal basis and a storage limit. Guidance on append-only ledgers asks for
  erasure by design and for every mapping to a person kept off the chain (EDPB guidelines 02/2025, applied here by
  analogy). Edges hold copies: bundles, logs, evidence and session recordings. Backups are object-locked and cannot be
  edited. The legal questions this raises are for each deployer's data protection officer; the engine provides the
  controls they need.

## Decision
1. **The log carries a random internal anchor per person.** The identity provider's id lives only in a mutable,
   erasable mapping table. Bundles carry the internal anchor and the username an edge needs (a gateway user, a
   directory bind). Erasing the mapping and the identity-provider account leaves a history that points at nobody.
2. **The deployer sets the log's retention.** Old segments are dropped behind a signed snapshot that the witness
   co-signs, and that snapshot becomes the new trust root. This amends 0022's guard that a restore replays the chain
   from the genesis. Nothing is deleted until a period is set, and the setup asks for one. It is built with signed
   snapshots and backup in 0.27.0, after its own adversarial review.
3. **Erasure reaches the edges like a revocation.** A signed erase-by-anchor request goes to each edge. Each edge
   returns a receipt (`kc-edge-erase-receipt-v1`), sealed by its enrolment key: the stores erased, the recordings
   destroyed, and what is still pending. An offline edge is queued, and the request stays pending until its receipt
   arrives. Text logs on the edge cannot be scrubbed reliably per person; they are a named residual, handled by
   retention.
4. **Session recordings have a key each.** Deleting a recording means destroying its key, by person or by recording.
   That also reaches copies in object stores and backups. A key copy held for break-glass expires with its recording.
   Recording is off until the deployer sets a purpose and a retention. The setup says what staff must be told.
5. **The e-mail an edge's gateway needs is transient.** Some gateways match a single sign-on by e-mail. The edge fetches
   the verified address with a signed request when it sets the credential, and never stores it in its bundle state.
   The bundle no longer carries `email`.
6. **Backups forget through an erasure journal.** The journal lists the internal anchors erased and when; it holds no
   personal data. Every restore applies it before the desk serves. A restore without it is refused.
7. **The migration strips before the genesis.** Moving from the signed YAML store, the migration re-keys every anchor
   to an internal one and strips names from reason texts. The signer verifies the last signed YAML revision, applies
   the re-keying, and checks that the result equals that revision except for the mapping. The genesis records the
   revision's hash. The old-to-new map lives only in the erasable table. Purging the old YAML revisions and their
   version history is the deployer's step, with a checklist in the migration runbook.

## How identity crosses the boundary (2026-10-25, after an adversarial review)
- The mapping table and the commitments are the authority; the broker never holds the internal anchor. A Keycloak
  attribute as a checked hint was weighed and rejected: a realm administrator controls a user's subject and attributes
  together, so a hint adds no protection, and it would put (broker id, internal anchor) pairs into the broker's backups,
  exports and events, where erasure cannot reach.
- From the anchor attribute to the subject, in two phases. The migration's mapping rows hold each person's anchor as
  the broker's anchor attribute carried it. Until the reconciler links a row to the person's broker subject, a sign-in
  or a proof naming that anchor resolves through the mapping, as before. Once linked, only the subject counts, so an
  attribute moved to another account names nobody (`anchors.resolve`).
- Approval proofs are verified when the signer signs. It counts only the proof errors a change adds, so a proof whose
  token is erased later never becomes an error; the token itself lives in an erasable side table, the log keeps its
  digest.

## Accounts, and the desk's boundary (2026-10-25, building the desk on the store)
- An accounts record per internal anchor (operator, 2026-10-25). Many accounts have no person record: owners,
  approvers and contacts named only in memberships, delegations or a connected organisation. Commitments kept in
  person and lease records would leave those mapping rows unvouched, so a desk could re-point them. Instead the log
  holds one accounts record per internal anchor, {anchor, commit}, which enters in the change that first names the
  account, with its mapping row; persons and leases carry no commitments. An accounts record never changes and leaves
  only by erasure. The signer refuses a link that names a person by anything other than an internal anchor an account
  stands for.
- The desk translates once, at its boundary. Sign-in resolves a token through the mapping (two phases, above); a
  request that names someone by the identity provider's id is translated to the internal anchor; a document the desk
  commits is re-keyed, with a new anchor, mapping row and accounts record for an account the store does not map yet.
  The engine's own actors (keyclerk:timer) name no person and are never re-keyed.
- A link keeps the structure of the desk's entry (change id, action, actor, outcome, records, visits by id only),
  never its free text: the summary and the reasons, which can name people, stay in the desk's activity log, whose line
  points at the link. Free text inside records (a reason a person typed) is the personal-data release's.

## Consequences
- The engine never claims "anonymous" or "compliant". It gives the deployer erasure, retention, restriction and
  receipts. Their DPIA states why an append-only history is kept, and for how long.
- A lookup by identity-provider id, and every write to the broker, goes through the mapping table.
- The genesis is a checked transformation of a signed revision, not a byte-for-byte copy of it. The transformation has
  its own tests.
- An edge that cannot reach the desk when a lease starts cannot set a credential that needs the e-mail.
- Open for real legal advice:
  - whether an internal anchor makes the history non-personal once its retention ends;
  - which bases cover keeping the history after an erasure request;
  - employee-monitoring rules for recordings;
  - whether re-applying a journal on restore is "without undue delay".
