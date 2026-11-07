# Changelog

Each release's notes come from its section here. Earlier entries are the releases' own one-line summaries;
the decision records (docs/decisions) hold the reasoning.

## 0.29.0-rc.1 (2026-11-07)
- HA change links and restore links can be confirmed by trustee signatures that every verifier checks (#41, F1). Their
  confirmations were hashes of broker tokens, which only the signer could check: whoever held the records key could
  sign HA off or break-glass with made-up hashes, and a desk adopted that link without the commit witness's
  countersignature, then followed anything after it; a restore link's mark could be pushed up the same way. A desk,
  signer, reconciler or commit witness that pins a trustee set now refuses those links, from the pinned position on,
  without one officer's and one root trust owner's signatures over a statement naming the link's position; and a desk
  that pins no trustee set no longer adopts any HA change link the commit witness did not countersign.

  Upgrading: write a trustee set (`kc-trustees-v1`, `python -m keyclerk.trustees check`), deliver it to every host out
  of band, and set `trustees: {set: FILE, since: N}` in each configuration, N the log's size when you pin it. To break
  the glass or switch HA off after that: `python -m keyclerk.ha nonce ... --trustee-statement FILE`, two trustees sign
  FILE (`ssh-keygen -Y sign -n keyclerk-trustee@REALM`), then `python -m keyclerk.ha sign ... --trustee-sig ID=SIGFILE`
  twice; restore links the same way through `python -m keyclerk.restore log-nonce` and `link`. Without a pinned set a
  break-glass link reaches desks only by following it by hand.
- A records-key recovery resets what the stolen key pushed forward (#41 F8, the fast-forward attack): the
  reconciler's high-water mark now names the history version it was signed under (`kc-mark-v2` after a rotation;
  `kc-mark-v1` until then), and once the reconciler's log holds a newer history, a mark from the older one and the
  last applied records count only up to the revision at the switch, with a `records_key_recovery` incident. Fence
  and revision elsewhere come from the links each store keeps, so a recovery's resync resets them.
- A records-key history held in a store's own state is never trusted by itself (0.29 review, N1). A store keeps the
  sealed versions it adopted and rebuilds them at every open from the operator's pinned history (configuration
  `records_keys`) against the pinned trustee set; without those pins it trusts only the log's first key, and a store
  that adopted a history it cannot verify refuses to open. The signer's own state is rebuilt the same way. A resync
  keeps the newest verified history the old store held (N5).
- A store started from a snapshot acts only once its records are the log's (the custodian review's D1): it keeps the
  links up to the snapshot, replays them into a store of their own and compares the records with the state the snapshot
  names. It reads meanwhile; the desk proposes and approves nothing, and the reconciler applies nothing, until the check
  holds. A state that differs (a signer's false state behind a true tree) is refused with an alarm, and the store
  resyncs from the genesis.
- What the checking signer counts is the same on both HA nodes (0.29 D3). With a change log, the signer writes its
  own records: each phoned unlock (`edge_unlocks`, so the hourly limit holds across a failover), each escrowed value
  and each custodian's confirmation (`edge_escrows`, `edge_escrow_confirms`, so either node answers the status), and
  each activated attestation key (`edge_activations`). TPM credential activation is done by the signer now (GET
  /edge/attest/challenge and POST /edge/attest/activate are passed to it), and an edge is assured only with an
  activation the signer recorded. No desk can write these records. On signed YAML the signer keeps them in its state.
- A bundle-key rollover needs each edge's officer (#41, F6; edge protocol 1.6): the signer begins it with a next key
  and a `kc-edge-key-rollover-v2` per live edge signed by the current key, each officer co-signs their edge's statement
  (`python -m keyclerk.edge_cli cosign`), and the signer finishes it only when every live edge's officer signature holds
  against the officer key in its records. An edge accepts only both signatures for its own edge and pinned key; the
  old-key-only v1 is refused. The old key is kept as `bundle-retired-N.key` until destroyed. Not yet in HA mode.
- The commit witness never trusts its own `keys.json` (0.29 review, N2): it keeps the sealed versions it adopted and
  rebuilds them at start from `--records-keys` (the highest pinned version of that log) against `--trustees`, and
  refuses to start when it holds versions it cannot verify. A history whose window names an origin another witnessed
  log holds is refused (N3). `--trustees-since N` lets an existing witness pin trustees without refusing the HA and
  restore links written before them (N7).
- The desk's activity log is verified against the keys of the history its own store verified, never against what the
  signer offers (0.29 review, N4), and the desk remembers the newest key that signed a line: a full check of a log
  rewritten whole with an older key reports it.
- At every records-key switch a follower's root must be the one the history's trusted checkpoint names (0.29 review
  N6): a store, a replay check and a snapshot adoption refuse the link that would reach a switch with another root, so
  whoever holds an older key cannot hand a new or lagging follower a fork of the links before the switch.
- HA mode needs a pinned trustee set (0.29 review N8, the maintainer's decision): the signer refuses to run as an HA
  node, to change HA, or to write a restore link without one; a desk refuses to follow a log in HA mode without one;
  and the commit witness does not start without `--trustees`. Without a pinned set the records key alone would decide
  HA changes and restore links.

  Upgrading an HA deployment: write the trustee set and pin it everywhere first (`trustees: {set, since}` in each
  configuration, `--trustees` with `--trustees-since` on the commit witness), `since` the log's size when you pin it,
  so the HA links written before it stay valid.
- A checkpoint note's tree size is refused past 2^53-1, as every other signed number is (the custodian review's
  A1): a size past any real log could otherwise ask a witness to countersign a forged tree.
- Access reviews (0.29 review R1, R2): a keep decision by someone revoked for cause from a time before the keep, as
  known when the review is judged, no longer counts; and a person's unit changes in the records only with a later
  `unit_since` (which never goes back or away), so the mover's grace can no longer be skipped. The person is found by
  any of their anchors.
- Access-review keeps are signed and keyed (0.29 review R3, R4). Where approval proofs are required, a keep carries
  its reviewer's own fresh sign-in, as a high-risk change carries its proposer's, and the checking signer refuses a
  keep not dated at its change. A keep made after the membership lapsed brings access back, so it counts only with a
  second key from someone with the members power over the group: the desk holds it until one is given. A keep before
  the lapse still needs only the reviewer. Review decisions may carry `approved_by`.
- A carried visit lease is sealed only when the edge's bundle would carry that visit lease (0.29 review, S1): its
  officer independent of the core, inside the ceiling the officer signed at the edge's attested profile, the person's
  hardware key not ended, no cross-edge exclusion holding the person elsewhere. Before, the signer carried any live
  visit lease, so a taken-over desk could carry one for an ended, stolen key.
- A carried visit lease is the person's own signature where approval proofs are required (0.29 review S1): the
  person signs in again for it (POST /me/visit-leases/{id}/carry-sign-in; the desk's Keys view does this and saves the
  lease file when the sign-in returns), and the checking signer seals it only on that sign-in, at most ten minutes
  old and used once.
- A break-glass promotion's activation time must lie inside its statement, from its `at` to its `not_after`, and a
  new activation needs a statement newer than the one the node's last activation used (0.29 review S10).
- The verified address of a lease's person is sealed only for a lease a bundle would carry now (0.29 review S11):
  a lease a cross-edge exclusion holds on another edge, or of a class without a horizon, gets no address, and the held
  ceiling is checked against its floor.
- The checking signer judges an edge's TPM attestation itself (0.29 review S12): a bundle request carries the edge's
  quote and signed request time, and the signer verifies the quote under the attestation key in its own records,
  requires the request to be at most five minutes old by its clock, checks the PCR baseline the officer signed and the
  endorsement key under the configured manufacturer roots. The desk's own "assured" claim no longer counts, so a
  taken-over desk cannot put visit leases into a basic edge's bundle. Credential activation is still the desk's step.
- The checking signer acknowledges escrow and evidence only from what it holds itself (0.29 review S2). It continues
  each edge's evidence chain and seals the head it verified; a desk that holds more catches it up from its own lines.
  It records each escrowed value's digest and its two custodians, and `confirmed` now needs both custodians' own fresh
  sign-ins, counted by the signer (POST /relay/{id}/confirm-sign-in; the Secrets view asks for it after showing a
  half). Opening a half alone no longer confirms it. Without approval proofs (approvals.proofs: required) an escrowed
  value is never confirmed, so the edge keeps it. In HA mode a node that did not record an escrow answers no status for
  it, and the edge keeps the value.
- Phoned unlock needs approval proofs (0.29 review S3, the maintainer's decision): the approver's own fresh sign-in
  signs each code, and the checking signer refuses an unlock without it, so no taken-over desk has a code computed on
  its word alone. Every code is an audit line at the signer. The desk counts an unlock toward the hourly limit only
  once it is computed, so a refused request uses up nothing.

  Upgrading: a deployment that uses phoned unlock sets `approvals.proofs: required` (docs/install.md, approvals as
  signatures); without it, phoned unlock is refused and says so.
- A phoned unlock's sign-in is taken by the checking signer only when it was issued in the last ten minutes by the
  signer's clock, and each sign-in reads one code (0.29 review S5); an escrow confirmation's sign-in is held to the
  same ten minutes. A desk that kept an approver's sign-in cannot have codes read with it later.
- The identity map's time is bounded both ways (0.29 review S7). A map more than five minutes ahead of the checking
  signer's clock is refused and no longer refuses every later map; a map older than `edges.identity_map_max_hours`
  (default 24) vouches for no bastion account, so bundles and addresses wait for the reconciler's next map. Run the
  reconciler at least daily, or raise the setting. The signer also refuses a new identity map while it is broken or
  frozen.
- Wallet groundwork hardened (0.29 review W1 to W5). A list of trusted entities signed by an issued certificate
  needs its issuer to be a CA allowed to sign certificates and the signer to carry id-tsl-kp-tslSigning; its sequence
  is bounded and moves at most 1000 past the cached floor; a cache name keeps one list (territory and type) and one
  list one name, whatever the case; malformed headers, certificates and statuses are refusals, a status counts only
  as granted, and an unreadable floor refuses until restored. The wallet registry checks every name along a claim's
  path against the identifying PID names (more of them now), compares a registration path by path (the export lists
  paths as arrays; export again), needs `--registration` or `--draft`, and `dcql` refuses a registry the check refuses.
- A break-glass promotion of a high-availability edge's node carries an expiring statement (#44, edge protocol 1.6):
  the desk refuses a promotion after its `not_after`, and one whose statement is not newer than the node's last
  recorded activation, so a statement found later cannot promote the node again. `edge_cli site-statement --purpose
  promotion --hours N` writes one valid for N hours (at most 24). **Upgrading:** an edge implementation that promotes a
  node sends `kc-edge-site-v2` from this release; a 1.5 promotion statement is refused.
- The desk keeps no key that grants (decision 0021 point 1): every bundle and every object an edge verifies under the
  bundle key comes from the checking signer, and so does every phoned unlock code, which the signer computes only
  after its own records allow it (an unlock approver of the edge, never the person, inside the edge policy's minutes
  and hourly count, kept by the signer). A desk without `--signer` serves no edge. **Upgrading:** move the desk's keys
  into the signer once (`python -m keyclerk.signer import-bundle-key --state DIR --from bundle.key --unlock-from
  unlock-v2.key`, enrolled edges keep their pins); the desk refuses edges while either file still lies beside its store.
- The failover model (docs/specs/SignerFailover.tla and its explorer) holds each node's key custodian as the authority
  on positions (decision 0033 point 9): one body per position, never below its witness floor, a start behind the
  witness that raises the floor and signs nothing until it has followed, a follow only onto the witness's tree and never
  below its own size, the ceremony only for a stuck custodian. TLC checks it clean (49,261,604 distinct states);
  switching off the floor raise or D2 each yields a counterexample.
- Every consumer of the change log follows a records-key rotation (#41, review finding F4): a backup verifies each
  copied change log with its own history and the signer's audit chain across the rotate line; a restore from a
  follower verifies both chains with the restored state's history, so after a recovery a follower that still holds
  what the stolen key signed is refused, never pulled back into the signer; the witness mark takes the key of the
  origin it checks; the desk's activity log verifies against the history's keys in order, and an older key's line
  after a newer key's line is refused; and a desk or reconciler adopts a newer history before it catches up, so the
  new key's first link is taken rather than refused (a signer from before 0.29 simply offers none).
- The edge command line says what would fail later (issues 50 to 52, from an install walk): `edge_cli statement`
  refuses an officer given as an account name (no anchor scheme) before anyone signs, `--account` when meant;
  `edge_cli ceiling` warns when it names no persons, and when its longest lease is under a day; `--max-lease-hours`
  defaults to 24. A lease longer than an edge's ceiling is still dropped, never shortened, so the desk now warns at
  the grant (`warnings` in the change's answer, shown under Note) when a membership outlasts an edge's ceiling;
  rolling leases that fit the ceiling are planned for 0.30.
- Upgrading with edges (0.29 review S8, the maintainer's decision): the bundle and unlock keys imported into the
  signer are the ones the desk held until now, so a copy taken from a desk compromised earlier would still work. Right
  after `import-bundle-key`, roll the bundle key over to one made in the signer (`python -m keyclerk.signer rollover
  begin`, each officer co-signs with `python -m keyclerk.edge_cli cosign`, then `rollover finish`; see the install
  guide, "Rolling the bundle key over"), and give every edge node a new unlock key through its
  officer-cosigned node statement. Then destroy the imported files and `bundle-retired-1.key`.
- Upgrading from 0.26.x straight to this release: every requirement since then applies, not only this release's.
  From 0.27.0: `approvals.acr` in the configuration (`python -m keyclerk.init acr ... --write`, or `acr: none`), and
  the reconciler's `--mark-key` (an Ed25519 private key as 64 hex digits, readable only by the reconciler's user; the
  reconciler alone signs and verifies the broker's high-water mark with it), run once with `--adopt-mark` where 0.26.x
  left an unsigned mark. From this release: see its own Upgrading lines. `python -m keyclerk.init check --config FILE
  --for SERVICES` with each service's command line names everything missing; the 0.28.0 note ("nothing new is
  required") was true only from 0.27.x.
- The access-review setting only tightens in place (0.29 review W6): the records guard refuses a revision that
  switches reviews off, lengthens the interval or the grace, moves `from` later or adds a parent principal. Relaxing it
  is the root trust owners' re-establishment of the records.
- Access reviews, derived (#42): with `reviews: {max_age_months, grace_days, from}` in the records, a named person's
  membership is due for review `max_age_months` after its start, its newest keep decision or `from`, and stops
  counting (`unreviewed`) `grace_days` later. The group's owner, or a named parent IGA principal, keeps it with the
  action `review_membership` (a `review_decisions` record, never changed or deleted); a revoke is `end_membership`. A
  person's `unit_since` makes their memberships from before the move due at once (the mover's grace). Without the
  setting nothing changes.
- Wallet groundwork (#43, no wallet yet): `python -m keyclerk.wallet_registry check|dcql|export` reads the home's
  registry of intended uses, generates each use's DCQL query and the registration export, and refuses a query that
  differs from the registration, an identifying attribute in a use that allows pseudonyms, a use without its
  privacy-policy URL, and a format outside the pinned version table (the versions HAIP 1.0 names).
  `keyclerk.lote` reads ETSI TS 119 602 lists of trusted entities, signed as JWS, under pinned signer certificates,
  and keeps them verbatim in a cache whose sequence number never goes back; a stale list counts as absent.
  An example registry: `docs/examples/wallet-registry.yaml`.
- Container images with every release (#49): `ghcr.io/keyclerk/keyclerk` and `ghcr.io/keyclerk/keyclerk-custodian`
  (static, on an empty base), linux/amd64. The release workflow builds each twice from the tag with the commit's time
  and stops unless the digests agree, tests and scans it in the image (a fixable high or critical finding stops it),
  then attests a build provenance and an SBOM and signs the digest with cosign (keyless). A daily job rebuilds the
  latest release on a base image whose digest moved, signed the same way. The README says how to verify and pin by
  digest. The Containerfile is multi-stage, its dependencies in a virtual environment without pip, and writes no dated
  files.
- The checking signer can build and seal an edge bundle itself (`seal_bundle`, `keyclerk/edge_sealer.py`): from its
  own replica it derives every lease, visit lease and revocation, names each lease's bastion account from the
  reconciler's sealed identity map under a pinned key (`Signer.configure_identity`), keeps its own floor for each
  edge's serial and ceiling serial, and seals with a bundle key the desk never sees. A desk's `bundle.key` moves in
  once, so enrolled edges keep their pin. It seals the other objects an edge verifies under that key too (`seal_edge`):
  an ended notice only when the records end the edge, naming every node's key; a time answer from its own clock; an
  e-mail answer only for a lease that person holds now, its address from the identity map; a carried visit lease
  rebuilt from the records with a floor per person on its serial; and the acknowledgements after a check of their
  shape, with the signer's own time. It cuts from its change log, or before a migration from the YAML revision it
  signed last. The desk does not use it yet; the next stage switches it over.
- Bastion accounts are named only from the reconciler's sealed identity map (decision 0021 point 2). The reconciler
  seals `identity-map.json` with its existing `--mark-key`; the desk passes the map on to the checking signer when it
  changes, and the signer keeps the newest it accepted under the reconciler key it pins (`--identity-key FILE`).
  `python -m keyclerk.init identity-key --mark-key FILE --out FILE` writes that public key; `python -m keyclerk.init
  bundle-key --out FILE` makes the one bundle key every node of an HA core imports, since a node in HA mode never makes
  its own. **Upgrading:** in this order: the reconciler (it writes the map at its next run); the signer with
  `--identity-key` (and, for an HA core, the same bundle key imported into every node with `python -m keyclerk.signer
  import-bundle-key`); then the desk, after moving its `bundle.key` into the signer. A desk that finds the reconciler's
  `usernames.json` but no sealed map keeps serving bundles, so ends and revocations still reach every edge, but no
  lease names an account: each edge gets one `identity_map_missing` incident naming these steps. A signer with
  `--identity-key` and no map yet, or a map under another key, refuses the bundle with the next step.
- The reconciler seals an identity map at every run (`identity-map.json` in its state folder, `kc-identity-map-v1`):
  each person's broker username and verified e-mail, bound to the realm and to the time it was read, signed with the
  key of its high-water mark. The checking signer will refuse a lease whose username or e-mail the newest map does not
  hold, so a taken-over desk cannot point a lease at another account. Nothing to configure yet.
- Where approval proofs are required (`approvals.proofs: required`), a phoned unlock is the approver's own signature:
  `POST /edges/{edge_id}/unlock-sign-in` starts a fresh sign-in whose nonce is a statement over every field of that
  one code, and the checking signer verifies the proof before it computes the code; the code is shown on the page the
  sign-in returns to, never in a URL. A proof for another unlock, or by another person, is refused. The desk's unlock
  form asks for the node of a two-node edge.
- Cross-edge exclusions: `edge_exclusions` names edges of which one person holds access on one at a time (a twin
  site, a second plant). The root or the security officer sets one with the action `exclude_edges` and ends it with
  `end_edge_record`. The records check refuses visit leases and direct memberships that would put one person on two of
  its edges in overlapping windows, naming the records; the bundle derivation, which the checking signer runs too,
  keeps exactly one of two overlapping entries (the earlier stable start, then the edge listed first) and lists the
  other as dropped with its reason, so access through rules and included groups is held apart as well.
- `keyclerk-custodian` (#40, decision 0033), a small Go process that holds the records key: the checking signer asks
  it to sign (`--custodian ADDR` instead of `--key`). It signs a link only at the next position, naming the last link's
  hash, in its realm, in the exact canonical form every verifier accepts, one body per position; a checkpoint, snapshot
  statement or checkpoint note only over the tree it computed; a log line's hash; nothing else. It never goes below the
  witness's countersigned checkpoint (read at start; required, `--unwitnessed` for development) and never signs a
  position twice. Its state is sealed under the key and written before every answer; a missing state is never a first
  run; one process holds a state; over TCP every request carries a token. A log reaches it only through the two-person
  recovery ceremony; a state moves between machines once (`export` retires the old one, `import` only raises); a planned
  rotation overwrites and removes the old key file. Two signer nodes each run one, the standby's following the committed
  log on the witness's word; a restarted standby behind the witness follows before it signs. With a TPM, `seal-key`
  seals the key file to the machine's boot state, and `tpm-init` with `--tpm-counter` binds the state to a TPM
  counter, so a state copied back from an older backup is refused even without the witness; a separate PKCS#11
  build (`-tags pkcs11`) keeps the key in a token such as a YubiHSM 2. After a recovery the signer records it in
  the log once (`custodian_recoveries`). Hardened after a five-angle adversarial review
  (the review of 2026-11-07).
- The commit witness follows the records-key history (#41). Started with `--trustees SET.json` and the log's history
  (`--records-keys FILE`), it adopts a newer version through `POST /keys` once it holds against that trustee set and
  rests on the witness's own countersignature; it keeps it across restarts (so a restart never brings the old key back
  and never refuses to start), takes the new key's links into the same log under the new origin, and refuses a
  checkpoint signed under an origin the history does not have in force. It refuses a recovery that would cut links it
  holds: reseed it from the trusted links. Its `--trustees` also pins the set HA change and restore links are checked
  against there. In HA mode, hand the new version to the commit witness (`CommitClient.keys`) before the new key
  signs its first link.
- The records-key history (`keyclerk.records_keys`, #41): a document the trustees sign (`kc-records-keys-v1`) that
  says which records key, under which log origin, signs which links. A new version is signed by one officer and one
  root trust owner, its new key proves possession, its earlier windows only clip at the switch, the switch is never
  inside a retired key's era, and it rests on a checkpoint the old key signed and the witness countersigned at the
  switch. Planned rotation and recovery after a compromise are the same step; a recovery switches earlier, and the
  links the stolen key signed after the trusted checkpoint are dropped. Consumers follow it in the next increment.
- The rotation ceremony on the command line: `python -m keyclerk.records_keys statement | seal | verify | rotate`
  writes the next history and what the trustees and the new key sign, seals it (verified against the pinned version
  and the trustee set before it is written), checks a sealed version, and moves the stopped signer to the new key.
  docs/install.md, "Rotating the records key".
- The signer rotates its records key (#41). `rotation_statement` writes the next records-key history at the signer's
  size: the newest window closed there, the new key's window opened under its own origin, resting on the witness's
  countersigned checkpoint at that size. Once the pinned trustees have signed it and the new key has accepted it,
  `rotate` switches the signer to the new key (a recovery first restores the signer to the trusted checkpoint). The
  old key signs a last audit line naming the new key, and the audit chain follows it only to the history's next key;
  a signer started afterwards with the old key signs nothing. The signer serves its histories (op `records_keys`) and
  its witness origin follows the key in force. The command line to run the ceremony comes next.
- Stores and followers follow the records-key history (#41). A store keeps the key it was created with and the newest
  verified history it adopted, and checks every link with the key in force at its position; a process can pin a
  history version in its configuration (`records_keys: {history: FILE}`), delivered out of band like the trustee set.
  A follower takes the newer versions the signer offers, each verified against the pinned trustee set: a planned
  rotation is adopted in place; a recovery resyncs from its switch, drops the links the stolen key signed after the
  trusted checkpoint and keeps the old store file as evidence. Without a pinned trustee set it adopts nothing and says
  so. A resync after a rotation keeps the history; the desk reopens its replica with the log's first key.
- Trustee keys (`keyclerk.trustees`, groundwork for #41): a trustee set (`kc-trustees-v1`) that every verifier pins in
  its own configuration, apart from the records key, with at least two security officers and two root trust owners
  and nobody in both roles. A trustee signs with a FIDO2 key (SSHSIG `sk-ssh-ed25519`, user presence required), a
  smartcard through an SSH agent (SSHSIG `ssh-ed25519`), or a raw Ed25519 PIV key; the threshold is one officer and
  one root trust owner, two people; a next set needs that threshold and each new key's proof of possession, and its
  version never skips. `python -m keyclerk.trustees check|statement|verify`.
- An edge can say why it holds no lease (#52, edge protocol 1.6): the signer carries what it left out of a bundle,
  and why, in the bundle's `dropped` (bounded; a null lease id for a reason that holds for the whole edge), and the
  verifier hands it to the agent. The desk's view of an edge adds `dropped_at`, the issue time of the bundle its
  dropped list is from: the list changes only when the edge pulls.
- `python -m keyclerk.signer rollover begin|finish` runs the bundle-key rollover with the signer stopped (#41 F6),
  and two signer nodes roll over together: the next key is made once and each node begins from it (`--next`), then
  both finish with the same officer-signed statements, the standby first.
- The desk, the console, the management listener and the witness listen on IPv6 (#37): a host with `:` (`::`,
  `::1`, or in brackets) binds IPv6, and `::` takes IPv4 too where the system allows dual-stack sockets, so one setting
  serves IPv4, IPv6 and dual-stack hosts. Before, the listeners were IPv4 only: `--host ::` failed at start, and on an
  IPv6-only pod `0.0.0.0` could not be reached, so the health probes restarted the desk again and again.
- Trustee sets and records-key histories (0.29 review N10): a process pins one trustee set (another is refused); a
  malformed set is refused with reasons; an SSH signature's reserved field must be empty; a follower takes a valid
  history version offered after one that does not hold, and versions in any order; `python -m keyclerk.trustees next`
  verifies the next trustee set before writing it; and a records key stolen before it signed its first link can be
  replaced at its own start, the replaced key never used again.
- `python -m keyclerk.witness reseed` reseeds a commit witness for a log whose records key was rotated (0.29 review
  N9): give `--records-keys` (the log's pinned history) and `--trustees`; every link and the seed checkpoint are
  checked under the key in force there, and the restarted witness keeps the history.
- A membership overdue for review is treated as live where it matters (0.29 review R5, W6): it can be ended at the
  desk, through SOAR and from the group view, the person's graph shows it as overdue instead of hiding it, and adding
  the same person again is refused, so a new membership cannot reset its review clock. The API contract lists the
  `unreviewed` status.
- A new bundle key (or any edge key file) is written whole and synced under a temporary name, then linked into place,
  and read under its own lock (0.29 review S9): a crash leaves no half key, and two requests at once make one key.
- Cross-edge exclusions (0.29 review X1 to X3): the checking signer's scoped check now reaches an exclusion's
  overlap from any change to memberships, visit leases, edges, revocations or groups, so it is never dropped; an
  exclusion can be ended (end_edge_record with its id, a second key as for other endings); and an exclusion governs
  from its own time, so overlaps that ended before it no longer refuse it.
- A cross-edge exclusion's tie-break is fair to derived leases (0.29 review X4): a lease through an included group
  starts at the later of the inclusion's start and the person's start in the included group, the same on every edge,
  instead of always losing. A visit lease starts now or later: the desk and the checking signer refuse one that
  starts in the past, so a backdated lease cannot win the tie-break.

## 0.28.0 (2026-11-06)
- At least once an hour an edge records a new anchor for its trusted time, the later of the wall clock and the
  anchor plus the boot clock since (edge protocol 1.5, section 1): a boot clock frozen while the wall clock is honest
  loses nothing, a wall clock set back while the boot clock runs gains nothing. `keyclerk.edge.ratchet` is the
  reference; the conformance family `ratchet` holds the freeze, thaw and set-back case and the sub-skew one.
- The edge policy judges a lease's or visit lease's start on the earlier reading (`now_start`, edge protocol 1.5) and
  its end on the trusted time, so a wall clock set forward cannot open a lease early; a bundle never re-anchors an edge
  after a reboot (only the desk's time answer does), and its reductions are stored at once (found by the platform
  model's adversarial review). Three new admit cases in the conformance set; the edge module changes.
- `keyclerk.edge.start_time` gives that earlier reading from a start anchor set only by verified time, never by the
  ratchet, so a wall clock set forward stays refused across wakes; conformance family `start_time` (5 cases).
- Edge protocol 1.5 states the edge's trusted time (section 1): the wall clock, or the wall clock at the last verified
  bundle plus the boot clock since it when that is more than 5 minutes later, and nothing live after a reboot until a
  fresh bundle verifies. Version 1.4 said only "the later of the clock and the newest signed time", which a clock held
  still defeats while an edge is cut off (decision 0032 point 35, adversarial review T1). the edge implementation's
  agent already does this; `keyclerk.edge.trusted_time` is the reference and the conformance family `trusted_time` holds
  seven cases.
- `python -m keyclerk.init check` checks a planned deployment before anything starts: the configuration whole, and for
  each service (signer, desk, reconciler, witness) its settings and, given its planned command line, every missing
  flag, missing file and rule between flags, all at once. docs/deployer-contract.md, generated from the new
  `keyclerk/contract.py`, says what each service needs; a test keeps it in step with each service's command line, and
  a release whose contract changed must carry an Upgrading line. The install guide gains the recipe for a Keycloak
  realm without a level-of-authentication flow (name the passkey level before setting clients' default level).
- **Upgrading:** nothing new is required to start the services in 0.28.0; run `python -m keyclerk.init check` with
  each service's command line to see that, and to catch anything 0.27.0 already required (`approvals.acr`, the
  reconciler's `--mark-key`).
- The officer's tools for relays and the site key (decision 0027): `edge_cli relay-cert` writes the certificate an
  officer signs for a relay key (edges, operations, a serial, at most 31 days), and `edge_cli site-statement` the
  statement the site key and a node sign for a provisional replacement or a promotion; `edge_cli cosign` signs each
  under its own format, so neither passes for an officer statement or for the other purpose.
- Relays and the site key, the reference formats (decision 0027, `keyclerk/edge_relay.py`): the officer certifies a
  relay key for a list of edges and operations, for at most 31 days (`kc-edge-relay-v1`); the relay seals tightenings
  (`kc-edge-tighten-v1`) bound to that certificate, to the parent bundle serial and to a counter that only rises; an
  edge applies one only when every operation narrows its state (revoke or end a lease earlier, cut sessions, suspend,
  roll back to a release above its floor, hold). The site key and a node sign `kc-edge-site-v1` statements for one
  purpose each: a provisional replacement, or a promotion.
- A node of a high-availability edge reports how it became active (edge protocol 1.5, decision 0031): the desk
  keeps the active node, raises an incident when it changes, and verifies a break-glass promotion against the
  edge's site key (`edges[].site_key`), an incident in itself.
- A desk follows an HA change link (HA off, a break-glass, another commit witness) at the next position even though
  no commit witness countersigned it, then follows under the configuration it sets; before, a desk holding HA on stopped
  at such a link. A break-glass is noted once as a finding in the desk's activity log, for the officer's view and the
  SIEM export (decision 0031 point 10).
- The commit witness (decision 0031, `keyclerk/commit_witness.py`, `python -m keyclerk.witness serve --commit`): for a
  realm in HA mode, the one witness whose compare-and-swap is the commit point. A commit carries the links it adds;
  each is checked as an append is, the root is recomputed over every link it holds, and only then is the checkpoint
  countersigned, so of two racing signers one wins. It serves the committed links to a standby, cuts an unanswered
  tail after a crash, and is re-seeded from checked links (`reseed`), never from nothing. The `ha` head record names
  it in the signed log.
- Two signer nodes in practice (decision 0031): `--ha-node`, `--commit-witness` and `--ha-hold` start a signer as a
  standby with its HA loop. Only the active node serves the log, and only the links the commit witness took; an
  active node deposes itself when it sees another node's commit, and steps down when it cannot reach the commit
  witness for its hold time. The desk's `--signer` takes the nodes' addresses, comma separated, and moves to the next
  one on a standby or a lost connection. `python -m keyclerk.commit_witness seed` exports a stopped signer's log as
  the commit witness's seed. The install guide's "Two signer nodes" section lays it out.
- In HA mode a desk checks the commit witness's countersignature itself (decision 0031 point 6): the active signer
  node serves the countersigned checkpoint with its head and each answer, and the desk adopts links only up to the size
  it covers, both signatures checked and the root compared. A node that serves links it never committed, a checkpoint
  only the records key signed, or an answer without the countersignature moves no desk; the desk reads on and says why.
- In HA mode only the active signer node sends detection witnesses a checkpoint, and only at the committed size
  (decision 0031 point 8): a standby, or a node deposed by another's commit, sends nothing, so no detection witness can
  hold a head a takeover drops and halt the new active node.
- Switching HA on, off, to other nodes or to another commit witness in an existing realm, and break-glass when the
  commit witness is lost (decision 0031 points 3 and 10): `python -m keyclerk.ha nonce|sign`, offline with the signer
  nodes stopped. The security officer and a root trust owner each confirm the change by signing in with its statement,
  which names the change and the head it is made on. A planned change is signed only on the commit witness's committed
  head; a break-glass only while the commit witness is stopped, and it names the one node that signs on. The change
  log's link format refuses any other link that touches the `ha` record, so a desk's change never can.
- The signer in HA mode (decision 0031): `Signer.configure_ha(node, client)` makes it one node of an HA core. It
  starts as a standby and signs only while active; it answers a change only once the commit witness took it, and
  names itself in the link's entry (`node`). A standby follows the committed links and takes over, with a signed
  takeover link, when the committed head has stood still for its hold time. An active node that lost the race is
  deposed: it drops what was never committed, rebuilds its replica from the committed links and becomes a standby.
  A change whose answer was lost is committed and answered when it is asked again. An empty commit witness is an
  outage, never a log of size 0: it is seeded from the log with `reseed`.
- A high-availability edge is two nodes to the desk (decision 0031): an edge's record may state a second node
  (`node2`: its own enrolment key, unlock key and TPM, in the officer's statement beside the first), either node's key
  signs its requests, and the desk keeps each node's last pull and report apart; the edges view lists the nodes. A
  one-node edge is unchanged.
- Edge protocol 1.5: `GET /api/v1/edge/time` answers an edge's signed request with the desk's time
  (`kc-edge-time-v1`, sealed by the bundle key, echoing the request's nonce). After a reboot an edge re-anchors its
  trusted time on that answer, if it arrived within 30 seconds on its boot clock, and only then is a bundle live
  again, so a bundle held back and delivered with the clock set back cannot keep a lease alive (decision 0032, second
  adversarial review M1). `keyclerk.edge.verify_time` is the reference; the conformance family `time` holds six cases.
- A desk on the change log refused every edge enrolment ("escrow custodians are at least two different people", "the
  edge's officer is a person of the organisation"): judging a change on what it reaches, the working set loaded only
  the people named in a hand-kept list of person fields, which had none of the edge kinds' fields. It now also loads
  every person a record names by its kind's anchor paths (the list the 0028 re-keying uses), so an edge's officer and
  custodians, a visit lease's person and a place's steward are judged with their records. Found by the soak harness;
  `tests/test_edges_log_backed.py` holds it.
- An edge reporting a standing drift raised a new incident at every report, and past its cap of 60 incidents an hour
  the cap's refusal answered the report 500, though the report was already stored, so the edge sent it again and
  again. A drift incident is raised only when the drift changes, and an incident over the cap is dropped (counted in
  `keyclerk_edge_incidents_dropped_total`), never the report. Found by the interim soak.
- Two signer nodes in HA mode handed the active role back and forth at every hold time when nothing changed: a standby
  takes over when the committed head stands still, and an idle active moved nothing. The active now beats: at most
  every third of its hold time it commits its checkpoint again with no links, and the commit witness countersigns it
  at a later time; a standby counts that as the head moving (decision 0031 point 7, amended). Beats add no link. Found
  by the first soak, on a shared lab host.
- A signer in HA mode read the commit witness's answers with the C2SP witness's cap of one note (about 68 KB), so a
  page of a larger realm's committed links was cut mid-string and the change failed with a JSON error. The commit
  witness's answers are now read up to `MAX_COMMIT`, and any witness answer over its cap is refused, never cut and
  parsed. Found by the soak harness on a slower box.
- An active signer node whose own commit answer was lost (the witness took the change, the answer did not arrive)
  marked itself deposed, so for a whole hold time nobody beat and a takeover added a link. It now sees that the
  committed links are its own and stays active. A beat that gets no answer is not retried at every tick.
- An ended high-availability edge was told so for its first node only: the ended notice named node 1's enrolment key,
  so node 2 took the end for an outage and kept its leases to their horizons. The notice now names every node's key.
- A phoned unlock code was always computed for node 1, so node 2 of a high-availability edge could never verify one.
  The request names the node (`node`, the id the node shows) when an edge has two, and the code uses that node's own
  unlock key; a one-node edge needs no change. Both found by the edge implementation reviewing its two-node design.

## 0.27.0 (2026-11-04)
- A restore no longer brings back what was erased: `keyclerk.backup take` writes a signed erasure journal (erased visit
  ids only) beside each manifest, `keyclerk.backup erasures` refreshes it, and a desk is restored only with a journal
  at least as new as the backup. `restore resume` and the new `restore leave` (a desk on the change log) erase again
  what it lists before the desk serves (decision 0028 point 6).
- A signer restored from a backup signs no change until `restore recover-log` or the restore link has run, so it
  cannot sign at positions it lost.
- A backup of a desk on the signed YAML store was refused: its records signature was taken for a key. Fixed.
- Behind a reverse proxy the public scan budget is kept per client: `api.trusted_proxies` lists the proxy networks
  (empty by default), and only from a listed proxy does the desk read `api.forwarded_header` (`x-forwarded-for` or
  `forwarded`), taking the rightmost address that is not a listed proxy (decision 0029 point 7).
- The configuration is refused when `backup.retention_days` is longer than `store.view_log_keep_days`, so a backup
  never keeps a look the desk has deleted (decision 0029 point 3).
- A witness for the change log (decision 0022 point 5, `keyclerk/witness.py`): the signer sends each new checkpoint,
  as a C2SP signed note, to the witnesses in the new `witness` configuration section, with a consistency proof from
  what each last countersigned. A signer restored from an older backup, rollback mark included, stops signing when a
  witness proves by its own countersigned checkpoint that the signer is behind or holds another history; an unsigned
  answer never stops it. `python -m keyclerk.witness serve` is a small C2SP witness, and any C2SP witness works.
  An unwitnessed link becomes a readiness incident after `witness.incident_after_minutes`, and
  `witness.block_after_minutes` can block signing; it is unset by default, so a site cut off from its witness keeps
  working. New metrics: `keyclerk_witness_total`, `keyclerk_unwitnessed_seconds`.
- The officer's ceiling judges a lease by its hours rounded up (edge protocol 1.4), at the desk and in the edge's
  verifier: rounded down, a lease up to 59 minutes longer than `max_lease_hours` passed.
- The reconciler sees child groups under a managed group: on Keycloak a member of one is under the managed group in
  every token, yet was not read (review row E5, reproduced on Keycloak 26.8.1). Their members are now removed through
  the admin API and logged out, the child group itself kept, and each child group is a finding on the run.
- A guest of a visit sees their own entry in full and only the names of the other guests: not their vehicles,
  kit, badges or gate times (decision 0009). The host, the organiser, escorts and the front office see the visit whole.
- The reconciler signs the identity broker's high-water mark with its own key (`--mark-key`). A mark that does not
  verify, or records older than it, refuse the revision, but memberships the records never required are still removed
  and the run reports an incident, so a mark written in the broker by hand can no longer stop every removal.
- A write about something that does not exist gets the same refusal, in the same words and with the same next
  step, as a write about something that is not the writer's; only the root and the security officer get the plain
  answer. Authority is checked before an ended membership or a visit's attendees are mentioned.
- Every preview leaves a line in the activity log (`outcome: preview`, with what a change would have answered);
  previews are left out of `keyclerk_changes_total`.
- The view log never loses a look: a full `views.log` rotates to a kept archive (`views-<UTC time>.log`) instead
  of dropping its oldest lines, and archives are deleted after `store.view_log_keep_days` (default 400).
- **Upgrading:** `approvals.acr` is required (decision 0030 point 5): a 0.26.x configuration without it is refused
  at start, saying so. Run `python -m keyclerk.init acr --keycloak URL --realm REALM --config FILE --write` to add
  the realm's strongest published level once you confirm it, or write `acr: none`, which the desk and the signer
  report as a finding at every start (docs/install.md, "The sign-in level of an approval").
- **Upgrading:** the reconciler needs `--mark-key` (docs/install.md, "The reconciler's high-water mark"); run it
  once with `--adopt-mark` to sign the mark an earlier version left.
- Backup and restore drill: `python -m keyclerk.backup take` copies a running desk and its signer through SQLite's
  online backup and verifies the copy (each change log against the records key, the full check, the signer's audit
  chain). It streams through a private staging directory, leaves out every key and the replicas an earlier resync
  replaced, and encrypts the copy with age to the recipients the configuration lists (`backup.recipients`, at least
  two custodians), with a signed manifest. `shipped` records where and when a copy went off-site.
  `check` and `restore` check the manifest first and refuse a copy that does not match it; a restored desk starts in
  restore mode. `drill` restores the newest good backup into a scratch directory and reports the recovery time.
  New `backup` configuration section and metrics `keyclerk_backup_age_seconds`, `keyclerk_backup_drill_failed` and
  `keyclerk_backup_recovery_seconds`.
- Restore safety for the signed YAML store: `python -m keyclerk.restore` puts a restored desk in restore mode (no
  writes, not ready, edges answer 503 and keep their bundle) and resumes it above a high-water mark the security officer
  and a root trust owner confirm by signature, so no revision number or edge bundle serial is signed twice
  (docs/install.md, "Restoring a desk from a backup").
- Signed snapshots of the change log (`kc-snapshot-v1`, `keyclerk/store/snapshot.py`): the signer writes one to
  `state/snapshots` after each passing background full check when the log has grown, keeping the newest two. A store
  adopts a snapshot only while empty and only with the links up to it, each checked as an append checks it; the
  root, head and fence they reach and the state file's hash must be the snapshot's, so a snapshot spares the rebuild,
  never the history. A follower's resync can start from one, and refuses one that is not the signer's log.
- Audit events for a SIEM (#29, `keyclerk/siem.py`): the desk's signed activity log as OCSF 1.3.0 JSON. With
  `siem.reader_token_file`, the management listener answers `GET /audit/events?after=SEQ` to that token only; the
  cursor is the log's line number, so a reader gets every event once across a restart. `python -m keyclerk.siem
  forward` sends RFC 5424 syslog over TLS to `siem.syslog`, trusting only its `ca_file`, and resumes from a cursor
  that moves only after each message is written. Each event carries its line's chain position, signature and
  records revision; people are pseudonyms and refusals carry reason classes, not text.
- The change log's signer, restored from an older backup, takes its lost links back from a follower whose chain
  verifies and starts with the restored one (`python -m keyclerk.restore recover-log`), so it never signs at a
  position it lost; a follower that forked is refused.
- The change log has a restore link: when no follower holds the links a restored signer lost, it appends one link
  with no ops whose `restore` part names the confirmed mark and the proofs of the security officer and a root trust
  owner, and the numbering resumes at mark + 1 (`python -m keyclerk.restore link`; new log conformance vectors).
- A desk fetches the signer's snapshot (#28): the signer protocol gains `snapshot` (the newest signed snapshot) and
  `snapshot_state` (its state file a megabyte at a time), and a follower's resync starts from it when the signer
  has one, every link before it still checked and the state's hash compared, else from the genesis as before.
- Privileged roles granted in the broker around KeyClerk are findings (#29): the reconciler reads the realm's
  role-mapping admin events from a cursor and reports every `realm-management` role and every role named in
  `reconcile.privileged_roles` mapped to a user or group directly, with who made it. The desk notes each once in
  its signed activity log, for the security officer's broker view and the SIEM. Report-only: nothing is removed.
- A SOAR proposes protective changes only (#30): with `soar.protective`, its API client may suspend a person, end a
  membership or raise a situation level through its registered feed, never grant or approve. Each change is checked
  and signed like any other, authored by the SOAR's workload; it waits for the security officer, the root or a
  person on call where policy says so, when it touches a person on call, and past `max_per_hour`, which also
  records a finding. A feed raise the engine would cap is refused with the reason. The person view lists a person's
  suspensions.
- Approvers are reminded, never handed an action (#30): the desk writes `approval_waiting` when it first sees a pending
  change, `change_expiring` when it has `approvals.remind.expiring_hours` left (24) and `approval_escalated` after
  `approvals.remind.escalate_after_hours` (72, naming the root and the security officer too), each once, in its signed
  activity log. Each names the change and its next approvers and carries no link or code that approves.
- SOAR webhooks (#30, `keyclerk/soar.py`): `python -m keyclerk.soar forward` sends the event types each endpoint in
  `soar.webhooks` chose as CloudEvents holding the SIEM's OCSF event, signed per Standard Webhooks, at least once and in
  order per endpoint; a failing endpoint retries from where it stopped and holds no other's queue. Reminders name their
  approvers as pseudonyms, or as broker ids for an endpoint configured to route them to people. Off unless configured.
- An edge reports a bastion taking away a lease's assignment before the lease expired, on any bastion: the
  `lease_ended_early` incident names the lease, and the desk accepts it only for a lease of the edge's last bundle
  ended before its expiry (edge protocol 1.4, decision 0029 point 8).
- Edge protocol 1.4 report members, each optional (#31): the bundle carries the records head it was cut from and the
  edge echoes it, and the desk raises an incident when an edge applied records newer than it holds or a head its
  change log does not hold; removal confirmations per lease are kept (the first of each); an edge declares what its
  bastion enforces by itself (`bastion.capabilities`, unknown tokens kept apart, never refused); an evidence entry may
  name the lease its session ran under. The reference agent (`edge_cli`) echoes the head.
- Backup hygiene (decision 0019 point 2): `python -m keyclerk.backup escrow challenge` encrypts a fresh value to
  each recipient that matters, retired ones a kept backup needs included; a custodian opens theirs with the age tool
  and `escrow answer` records the signed proof. `backup hygiene` reports a key not shown within
  `backup.escrow_check_days` and a recipient in use past `backup.rotate_after_days`; new gauges
  `keyclerk_backup_escrow_unproven` and `keyclerk_backup_recipients_due_rotation`.
- The repository meta for working in public: changelog fragments (`changelog.d/`, `tools/changelog.py`), a
  public text check on everything posted (`tools/public_text_check.py` and its workflow), ROADMAP.md, CODEOWNERS, a
  code of conduct, governance, maintainers, support and name-use pages, and a time limit on every CI job.
- A restore's mark has sources (decision 0019 point 5): `python -m keyclerk.restore status` proposes the newest
  revision anyone saw from the records heads edges echoed while the desk was in restore mode (edge protocol 1.4)
  and, with `--witness`, from the witness's countersigned checkpoint, both signatures checked. Two people still
  confirm the mark.

## 0.26.3 (2026-10-26)
- The image's trust store leaves out the emSign roots that certifi 2026.10.19 dropped after the eMudhra intermediate
  key incident (emSign ECC Root CA - G3, emSign Root CA - C1, emSign ECC Root CA - C3), so the desk, the reconciler
  and the signer never accept a server certificate chaining to them; the base image's Python (3.12.15) does not
  reject the affected intermediates itself yet. `tools/distrust_cas.sh` does it, in the Containerfile and in CI;
  `tests/test_trust_store.py` checks it. Dependency installs were already safe: every one is hash-locked.
- 0.26.2 was tagged internally only; its section below is part of this release.

## 0.26.2 (2026-10-26)
Hardening after a review of the change log, the identity boundary and the reconciler (decision 0028, 2026-10-26):
- The checking signer has a second listener for the reconciler (`--reconciler-listen`, `--reconciler-token`), the only
  one that records a broker subject; the desk's listener refuses `link_subject`. **Deployments on the change log:**
  start the signer with `--reconciler-listen` and point the reconciler's `--signer` at it, or accounts are not linked
  to their subject (access still works by anchor attribute, as in phase 1).
- The reconciler links a subject only on an applying run, only for a membership the records want, and only when one
  account carries the anchor attribute; a removal removes the member the read found, so a copy of an anchor on another
  account never blocks it.
- The signer refuses a mapping row that carries a subject or an identity provider id starting with `sub:`, refuses
  `sub:` anchors, and checks a link's entry shape (no free text, no provider ids).
- A follower refuses a resynced log that does not extend the history it verified.
- Approvals recorded on situations, surge packages and leases need a proof (or a pin in
  `approvals.accepted_without_proof`), like every other approval.
- A proof whose token was erased is reported as such instead of failing the check.
- The reconciler's removal cap counts every anchored member when it has no earlier desired set (a first run or a
  lost state).
- The desk: a refused approval names approvers only to someone the pending view shows them to; the public scan
  budget forgets quiet addresses, so a full table never refuses everyone.
- Edges: a lease credential is relayed only to the holder of that lease; a rotation meets the enrolment's rules for its
  keys and officer; the address endpoint answers only what the officer's ceiling and independence allow at the time
  of the request.
- Edges: after a rotation to another officer or key, the previous officer's ceiling governs nothing (no leases, an
  incident) until the officer in force signs one.
- An approval that does not count as a key the change needs is refused, with the reason that names why (`X does
  not count: ...`), and the change waits as it did. Before, such an approval answered `pending` and was kept: a key
  that does not count only adds that tail to the reason it leaves open, and the desk took the changed text for
  progress, so the approver saw nothing change and no why.
- Dependencies: wasmtime 50.0.1 (the runtime the compiled policies run in), jsonschema 4.26.0, cffi 2.1.1,
  pycparser 3.12, rpds-py 2026.9.1; for tests pytest 9.1.1 (a tmpdir handling fix) and hypothesis 6.170.6. The image's
  hash-locked `requirements.lock` is regenerated from `constraints.txt` with them.

## 0.26.1 (2026-10-25)
- The compiled policy modules no longer carry the build machine's folders: the compiler kept each source's absolute
  path for its error locations, so a module named the folder it was built in and its bytes, which edges pin by hash,
  depended on where it was built. `tools/build_policy.py` now builds from the policy folder by file name, and the
  modules are rebuilt; only their hashes change (the edge conformance set's `modules`), not what they decide.
- The leak gate reads binary files too (local paths, keys, tokens, personal names), and skips tool caches.
- `docs/references.md`: the standards KeyClerk implements, the conventions it follows and the software it stands
  on, each linked, and checked by a test.

## 0.26.0 (2026-10-25)
The desk runs on the signed change log, and a running deployment can move to it (docs/migrate-to-change-log.md). A
YAML deployment that does not move is unchanged.
- The configuration chooses the desk's store (`store.kind`: `yaml`, the default, or `sqlite`, the signed change
  log, which needs the checking signer), and the desk reaches its store through one protocol
  (`keyclerk.store.desk_store.DeskStore`). The migration command no longer needs `--preview`.
- The checking signer, for a desk on the change log: a change proposed again after its answer was lost is answered
  with the link it already is, never applied twice; the mapping rows of new people enter only with the commitment a
  record of the same change carries, and never re-point a mapped anchor or account; a log can start empty (op
  `start`), its first change judged whole; a frozen signer still serves the reads a desk follows by.
- The desk on the change log (`keyclerk.store.log_desk.LogStore`): it proposes every change through the checking
  signer and follows its log, keeps visits in its replica's side tables, rebuilds a lost replica from the signer,
  and resyncs into a new file. The desk and visit test suites run on both stores.
- Identity on the change log (decision 0028): an accounts record per internal anchor vouches for every mapping row,
  persons or not (persons and leases no longer carry commitments); sign-in, requests and committed documents are
  translated to internal anchors at the desk's boundary; the signer refuses a link that names a person otherwise; a
  link keeps an entry's structure, never its free text. A visit timer's suspension was refused on the change log
  because the timer was taken for a person: the engine's own actors are never re-keyed.
- The reconciler on the change log (`--log-replica`, `--signer`, `--records-key`): it follows its own replica of the
  log, verified against the records key it pins, and refuses a mapping row the log's accounts records do not vouch
  for and a plan naming an account the mapping does not; it tells the broker its own names, links each account it
  sees to its broker subject (signer op `link_subject`, once, audited) and from then on addresses it by that
  subject, never by the anchor attribute; an attribute moved to another account names nobody. Erased mapping rows
  leave every replica.
- Edge protocol 1.3 (decision 0028 point 5): the address leaves the bundle (a lease's `email` is null) and an edge
  fetches it when it sets a gateway credential, `GET /api/v1/edge/lease/{lease_id}/email`, a sealed
  `kc-edge-email-v1` for a lease in the edge's last bundle and live now, bound to the request's nonce, six a minute
  per lease; `edge.verify_email` is the reference and the conformance set has an `email` family (the address by
  its digest). A lease's `person` is opaque: KeyClerk's internal anchor on the change log.
- Migrating a running desk (`python -m keyclerk.store.migrate STORE STORE/log.db --signer ...`): the replica is built
  where the log store opens it, pending changes are re-keyed and can still be approved, the YAML-era activity log is
  moved aside, and the history starts with one line, migrated from signed YAML revision n. The runbook, with the way
  back and the purge checklist: docs/migrate-to-change-log.md.
- Health of the desk on the change log: it follows the signer every 15 s; readiness says when it cannot follow
  (not ready, with the reason) and when signing is frozen (ready, read-only); `keyclerk_log_breaks` counts follow
  failures, `keyclerk_signing_frozen` and `keyclerk_timer_refused_total` are new. A stale write is refused whole and
  says to look again; with the signer down reads go on and writes are refused, never queued; a desk that stopped
  between a link and its activity line writes the line at its next start; a replica restored newer than its
  signer is refused, and a refused start releases its lock. The fault model, with a test per row:
  docs/testing/concurrency-and-state-machines.md.
- The desk on the change log judges a change on what it reaches, as the signer does: one shared function
  (`store/working.scoped_judgement`) over its replica with the change tried and rolled back (`SqliteStore.trial`),
  the full check only when a change reaches everyone; it commits the ops it judged, moves its records forward by
  each link, and syncs the mapping in one transaction. At 20,000 employees a desk change takes 3.4 s instead of
  47 s (docs/testing/realistic-load.md); `tools/bench_org.py` names people by internal anchors again (`--desk N`).

## 0.25.1 (2026-10-25)
- The package version agrees with the release again: 0.25.0's `pyproject.toml` still said 0.24.1, so an install
  from the v0.25.0 tag reported itself as 0.24.1. Use 0.25.1; a test now holds the two versions together.

## 0.25.0 (2026-10-25)
- The signed change log on SQLite (decision 0022): signed links in a hash chain, a checkpoint per change, the checking
  signer's own replica, migration from the signed YAML store (refused with the fixes when its last revision has engine
  errors), changes judged on the records they reach with a background full check that compares. A YAML deployment is
  unchanged: migrating to the change log is offered from 0.26.0, with the desk on the store; until then the migration
  command refuses without `--preview`.
- Internal anchors (decision 0028): the migration re-keys every person to a random internal anchor before the genesis,
  with a salted commitment in the log and the identity provider's id only in erasable mapping tables, so no identity
  provider's id enters the chain; proofs on the change log resolve through the mapping, in two phases toward the broker
  subject.
- Realistic load measured (`tools/bench_org.py`, `docs/testing/realistic-load.md`): at 20,000 employees and 5,000 groups
  a change takes 0.4 to 1.8 s, after two fixes (the subtree rate bucket per start day, the group map once per check).
- The edge bundle names the roles KeyClerk governs on the edge (decision 0025, edge protocol 1.1); an edge may wait for
  its next bundle (decision 0026, edge protocol 1.2); signed-request conformance vectors; the protocol's references.
- `keyclerk init` writes admin personas on a privileged top group.
- Engineering: ruff, REUSE compliance, hash-locked CI tools, ClusterFuzzLite fuzzing of the bundle verifier, the public
  repository baseline, decisions 0025 to 0028.

## 0.24.1 (2026-10-24)
- edge-era changes approvable with required proofs; relicensed to EUPL-1.2

## 0.24.0 (2026-10-24)
- the checks scale (0017), approvers without a full check per person, health, readiness and metrics (0018 H1 to H3)

## 0.23.0 (2026-10-24)
- one signing mode (0014d), modules by hash, kc-unlock-v2, bound ended notice

## 0.22.0 (2026-10-23)
- integer bounds, horizons, vectors, lease e-mail, stable from

## 0.21.2 (2026-10-23)
- edge verifier refuses, never raises

## 0.21.1 (2026-10-23)
- UI review fixes

## 0.21.0 (2026-10-23)
- TPM attestation for edges (decision 0016)

## 0.20.0 (2026-10-23)
- the checking signer and proposer proofs (decision 0015)

## 0.19.0 (2026-10-23)
- edges ready for a pilot (0014c) and the final UI pass

## 0.18.0 (2026-10-23)
- the edge trust model (0014a), what an agent needs (0014b), the interface and CLI

## 0.17.0 (2026-10-23)
- edges (decision 0014)

## 0.16.4 (2026-10-23)
- the desk UI upgrade complete (slices 4 to 6)

## 0.16.3 (2026-10-23)
- desk UI slices 2 and 3, the person graph placed by rules

## 0.16.2 (2026-10-23)
- desk UI slice 1 (foundations and accessibility), panels never show "null", retired memberships judged as made

## 0.16.1 (2026-10-23)
- the persona rule is enforced by default; a retired membership is not judged on who its member is today

## 0.16.0 (2026-10-23)
- visits outside the signed records, one fold per check, honest README

## 0.15.0 (2026-10-23)
- admin personas, change 1: every effective member judged, KeyClerk's own powers by account (decision 0011a)

## 0.14.0 (2026-10-23)
- personas, workloads and agents (decision 0011); API hardening found by fuzzing the contract

## 0.13.1 (2026-10-23)
- visit requests pass the API contract (attendee objects no longer require every field); an API-level test registers a visit; use case extended with two security firms, one federated (G12-G18)

## 0.13.0 (2026-10-23)
- person-first visits (decision 0010)

## 0.12.0 (2026-10-23)
- visit badges, a RESTRICTED badge signed out by two people (decision 0009)

## 0.11.0 (2026-10-23)
- the visit QR code and the phone scan (decision 0009)

## 0.10.0 (2026-10-23)
- visits, first slice, decided by a compiled visits policy (decision 0009)

## 0.9.0 (2026-10-23)
- the delegation tree, decided by a compiled tree policy (decision 0009)

## 0.8.1 (2026-10-22)
- every records kind survives a split; split files never carry YAML aliases

## 0.8.0 (2026-10-22)
- persona graph

## 0.7.1 (2026-10-22)
- free the compiled policy in order at exit (no access violation in wasmtime teardown)

## 0.7.0 (2026-10-22)
- second-key standing

## 0.6.3 (2026-10-22)
- the front end redesigned for clarity; second keys from the organisation only

## 0.6.2 (2026-10-22)
- fixes from an independent review

## 0.6.1 (2026-10-22)
- every failure says why, what completes the intent, and who can do it

## 0.6.0 (2026-10-22)
- use what the broker offers (decision 0007)

## 0.5.0 (2026-10-22)
- approvals as the approver's own signature (decision 0006)

## 0.4.6 (2026-10-22)
- the API page never prints the CSRF token; wider change cards

## 0.4.5 (2026-10-22)
- an API page built from the contract; need-to-know reads

## 0.4.4 (2026-10-22)
- conflicts, concurrency, interruptions and damaged state

## 0.4.3 (2026-10-22)
- the live desk attacked over HTTP, and what that found fixed

## 0.4.2 (2026-10-22)
- front end fixes from the first browser walk; refused attempts logged

## 0.4.1 (2026-10-22)
- the history guard compares times by meaning; a manager's key makes a change wait

## 0.4.0 (2026-10-22)
- the desk, its API contract and a front end (decision 0005)

## 0.3.1 (2026-10-22)
- a run whose log cannot be written is still reported and fails

## 0.3.0 (2026-10-22)
- hardened input and output at every seam; an adversarial review's findings dispositioned

## 0.2.0 (2026-10-22)
- the reconciler loop, the read-only console and the container image

## 0.1.3 (2026-10-22)
- Keycloak 26.8.1 as measured in the first end-to-end run

## 0.1.2 (2026-10-22)
- no review identifiers of a deployment in code, Rego or tests

## 0.1.1 (2026-10-22)
- the Rego ships inside the package

## 0.1.0 (2026-10-22)
- the engine, configuration-driven and named for no deployment
