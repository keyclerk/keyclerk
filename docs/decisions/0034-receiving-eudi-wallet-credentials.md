# 0034. Receiving EUDI Wallet credentials: KeyClerk as a registered relying party

- Status: proposed (2026-11-05), after its research (docs/reviews/2026-11-05-eudi-wallet-relying-party.md), an
  adversarial review (docs/reviews/2026-11-05-0034-adversarial review.md) and the maintainer's decision round the same day. The
  maintainer asked for it after decision 0032 Q8 ("receive first") and asked for more effort on the wallet path.
  Builds on 0032 (people, engagements, claims, the evidence ladder, points 18 to 29, A15 to A20, Q3, Q8), 0021 (every
  granting key in the signer) and 0033 (the key custodian).
- Context: from around 24 December 2026 every Member State offers a wallet and runs a register of relying parties
  (Regulation (EU) 2024/1183, art. 5b; implementing regulation 2025/848, amended by 2026/1730). A party that asks a
  wallet for data must first register, for each intended use, the data it asks for, and may ask for nothing more
  (art. 5b(3)); a wallet warns when a request asks for more than the registration certificate says (ARF RPRC_21).
  The duty to accept the wallet (art. 5f) concerns strong user authentication for online identification, so physical
  workplace access is not under it: acceptance rests on what buyers want. OpenID4VP 1.0 and HAIP 1.0 are final;
  SD-JWT is RFC 9901; SD-JWT VC and the Token Status List are drafts that HAIP pins at named versions. Every PID is
  issued both as SD-JWT VC and as mdoc (ISO/IEC 18013-5), proximity presentation is mdoc only, and Safari's Digital
  Credentials API carries only mdoc (ISO/IEC 18013-7 Annex C). Belgium's wallet (MyGov.be) has no public date,
  sandbox, registrar or access CA yet.

## Decision
1. **A home receives wallet presentations as evidence, never as decisions.** A verified presentation becomes a 0032
   claim through the wallet channel of Q8: the home's own checker, signer and person match still act, a local
   negative outweighs it, and it never reaches an edge.
2. **Each home registers itself** as a relying party in its Member State, per intended use, with the minimum data. The
   registry of claim types is the source: it generates the wallet queries (DCQL) and the registration export (Annex I
   of 2025/848), and the build fails when a query asks for an attribute that is not registered. A claim type that
   adds an attribute is gated on a new registration certificate held by the home, and at run time the request signer
   (point 3) checks the query against the certificate it attaches, not against our registry: the registrar is the
   authority. A home forwards to a peer home only its claim (a validation record), never the attributes, so it never
   acts as an intermediary (ARF RPI_01, RPI_10).
3. **The relying-party key authenticates the home; it grants nothing.** Under `x509_hash` the access-certificate key
   (P-256, one per registered service) signs every request; the registration certificate is the registrar's,
   carried by value; the encryption keys are ephemeral per request. So there is one long-lived key, and it is an
   authentication key, not a granting key under 0021: stolen, it lets someone pose as the home and collect people's
   data, never widen access inside the home, since the verifier never trusts it. It lives in a small request signer
   under its own operating-system user (or a PKCS#11 build once 0033 is amended for it), which signs a request only
   when its DCQL is a subset of the registration certificate attached; rotation and revocation go through the access
   CA, and a compromise runbook says how to tell the registrar.
4. **Four small processes** (amending 0032 point 27):
   - the **request signer** (point 3), which writes each request's state (nonce, state, audience, session, expiry);
   - a **responder** reachable by the wallet, serving `request_uri` and receiving the encrypted response: it accepts
     a response only for an open, unexpired state, once, caps its size, rate-limits, stores it by its hash and, in
     the same-device flow, returns a `response_code` the desk session must present (against session fixation);
   - a **fetcher** that pulls the lists of trusted entities (ETSI TS 119 602), the EU Trusted List and status lists
     on a schedule, whole, into a signed local cache; never at a presentation, which would tell the issuer when
     someone presented;
   - the **verifier**, without network, which reads the cache, the stored response and the request state, checks
     nonce (once), audience, state and session, re-checks the issuer's signatures itself, and writes the claim.
5. **Two verifiers must agree** (Q2). Our thin OpenID4VP and HAIP layer and an independent one (pyeudiw, or the EU
   verifier with an explicit issuer trust list, never its trust-all default) both accept, or the presentation is
   refused. Every disagreement and every refusal becomes a shared conformance vector; the parsers of encrypted and
   CBOR input are fuzzed.
6. **Profile and versions.** HAIP: client id prefix `x509_hash`, a signed request by `request_uri`,
   `direct_post.jwt` with ephemeral keys, DCQL. A version table pins HAIP, SD-JWT VC, the Token Status List, the ARF
   and ISO 18013-7 at the versions HAIP names, each with its vectors; CI fails on a version outside the table.
   Cross-device redirects get no channel; the Digital Credentials API's own hybrid (QR) flow, which checks proximity
   (ARF OIA_08g), is allowed.
7. **Trust anchors and status come from the governing lists** (amending 0032 A17). A list is verified under the
   signer set the Official Journal publishes, following its chain only; a list's sequence number never goes back. A
   status URI is followed only when its host is listed for that provider; issuers outside a list stay pinned per home.
   Nothing trusts an issuer by default. A desk past a list's next update, or offline past a status list's age, treats
   the claim as absent (0032 point 23).
8. **Rungs and matching.** Genuineness: the issuer chain reaches an anchor of a governing list (ceiling "high" for
   PID). Key-bound: the key-binding JWT or the mdoc device authentication over our nonce, audience and state.
   Person matched: at first contact the PID creates the proofing, capped by the channel's ceiling; against an
   existing person a match on name and birth date is only a proposal a checker confirms (0032 point 25), never an
   automatic merge (0032 point 3), and a collision on (name, birth date) blocks and opens a case. The keyed fact hash
   includes the issuing state. A national identifier is never requested as a match key (amending 0032 point 19). The
   level is the weakest rung, capped by the channel's ceiling per flow (same-device remote, the desk's API, proximity)
   and the issuer's FTEF band.
9. **What is kept:** the result, the key-binding digest and a keyed hash of the presentation under the evidence-pointer
   key of 0032 point 19, erasable with its side table; the presentation itself only under a dispute class (0032 point
   45).
10. **Hosting** (Q4). Each home is its own relying party. A provider may host KeyClerk as a GDPR processor under the
    home's own registration and access certificate, never as an intermediary under its own registration; a legal
    opinion comes before any hosted offer.
11. **Edges stay wallet-free** (Q5, on 0032 Q3: a cut-off site never judges new proof). A door use runs through a lease
    the desk judged; a carried lease resting on a wallet claim folds in that claim's status horizon and its maximum
    offline reliance (24 hours by default, 0032 Q7), shorter than the 72-hour carry cap.
12. **A pseudonym is a first-class presentation** (operator, 2026-11-06; 0032 A27 to A33). For an engagement kind that
    allows pseudonyms, the request asks for no identifying attribute: the wallet's pseudonym for this relying party
    and the attributes the kind needs (an age over a threshold, an employer attestation), nothing else. The PID path of
    point 8 runs only for kinds that require identification. The registration export lists the pseudonymous intended
    use apart, so the registration shows that a visitor is never asked for a name. Wallet pseudonyms arrive in later
    wallet versions; until a wallet offers one, a desk-issued visitor token or a passkey stands in.

## Stages, each with its done-when
- **W0, now (no wallet):** the registry generates DCQL and the registration export; a parser of TS 119 602 lists with
  a signed cache; the version table; a request without any identifying attribute for kinds that allow pseudonyms
  (point 12); per intended use, the privacy-policy URL the 2026 amendment of the registration act requires, and a
  request that matches the registration exactly (wallets warn the user on any request beyond it). Done when the CI lint refuses an unregistered attribute and an identifying attribute in a pseudonymous
  request, the parser reads the Commission's test list, and CI fails on an unpinned version.
- **W1, now (Q1: both flows together):** SD-JWT VC PID in the same-device remote flow (onboarding before arrival) and
  mdoc at the desk through the Digital Credentials API with both `openid4vp` and `org-iso-mdoc` (Annex C), with status
  lists, the two verifiers (point 5) and a mock registrar issuing registration certificates in the RPRC format. Done
  when the OIDF OpenID4VP 1.0 HAIP verifier test plans pass for sd_jwt_vc and mdoc, the negative vectors refuse
  (wrong key binding, replayed nonce, unregistered attribute, revoked or suspended, untrusted issuer, a response for a
  closed state, a fixated session), one iOS and one Android desk presentation work, and a 0032 claim is written with
  its rungs.
- **W2, now:** hardening: fuzzing of the parsers, the compromise runbook for the access-certificate key, the request
  signer's subset check against a real registration certificate's format. Done when the fuzzers run in CI and the
  runbook is drilled once.
- **W3, now (Q7: everything up to Belgium):** an ISO 18013-5 proximity reader at the desk (BLE or NFC, reader
  authentication). Done when a lab presentation works, then at an interop event.
- **W4, waits for Belgium:** registration, the production access certificate, the PID list, MyGov.be. Done when one
  home is registered and one production PID presentation is accepted.
- **W5, waits for issuers:** EAA through the wallet channel (qualifications, the posted-worker PDA1, employer
  attestations), and from organisations' business wallets the legal person's identity and a mandate to represent it
  (the European Business Wallet, COM(2025) 838, in trilogue). Done when one external EAA maps to a claim type with its band cap.

## The maintainer's answers (decision round, 2026-11-05)
- Q1 Remote SD-JWT VC and desk mdoc are built together, in one stage (W1): the in-person case is the distinctive one.
- Q2 Two independent verifiers must agree (point 5); our own layer alone would put our bugs on the accepting side.
- Q3 The Digital Credentials API first at the desk, its proximity-checked hybrid flow allowed, no redirect-based
  cross-device flow (by ARF OIA_08c and OIA_08g; defaulted).
- Q4 Each home its own relying party; a provider may host as a processor, never as an intermediary under its own
  registration; a legal opinion before any hosted offer.
- Q5 Doors and edges stay wallet-free (by 0032 Q3; defaulted).
- Q6 Name and birth date only as a proposal a checker confirms, never an automatic merge, never the national
  register number (by 0032 points 3 and 25; defaulted).
- Q7 Everything up to Belgium now (W0 to W3); only Belgian production and EAA wait. Against it, recorded: demand rests
  on buyers, since the acceptance duty does not cover workplace access.

## Consequences
- A home that uses wallets carries a registration, a DPIA per intended use, one authentication key in its own request
  signer, and four small processes; the build keeps queries, registration and pinned versions in step.
- 0032 is amended at point 19 (no national identifier), point 27 (intake in four processes), A17 (anchors and status
  from the governing lists) and A20 (the relying-party key, the intermediary rule), and gains per-flow channel
  ceilings; 0033 needs an amendment before it can hold the P-256 relying-party key.
- W0 to W3 are built before Belgium publishes anything; nothing reaches production before W4.

## Changelog
- 2026-11-05 Draft, from the EUDI relying-party research.
- 2026-11-05 Proposed: the adversarial review's amendments (the key class, four processes, the match as a proposal,
  pinned versions, Safari's Annex C, two verifiers, list fetching, registration drift, hosting, the carried lease's
  horizon, what is kept) and the maintainer's answers to Q1 to Q7.
- 2026-11-06 Point 12: a pseudonym as a first-class presentation, and W0's pseudonymous request (operator).
- 2026-11-06 W0: the privacy-policy URL per intended use and an exact match with the registration (CIR 2026/1730);
  W5: business-wallet credentials and mandates.
- 2026-11-06 W0 built (keyclerk.wallet_registry, keyclerk.lote). The version table pins what HAIP 1.0 itself
  references: SD-JWT VC draft-ietf-oauth-sd-jwt-vc-13 and the Token Status List draft-ietf-oauth-status-list-14, not
  the later drafts (-23, -21) the research recorded as current; RFC 9901; ISO/IEC 18013-5:2021. The Commission's PID
  list page says the first compiled list "is being prepared" and is not published yet (read 2026-11-06), so the
  parser was proven on a published signed LoTE (SIROS's test list under its published root) and on built vectors;
  reading the Commission's own list waits for its publication.
