<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/wordmark/keyclerk-lockup-dark.svg">
    <img src="brand/wordmark/keyclerk-lockup-light.svg" alt="KeyClerk" width="360">
  </picture>
</p>
<p align="center"><em>Every key signed. Every key returned.</em></p>
<p align="center">
  <a href="https://github.com/keyclerk/keyclerk/actions/workflows/ci.yml"><img src="https://github.com/keyclerk/keyclerk/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/keyclerk/keyclerk"><img src="https://api.scorecard.dev/projects/github.com/keyclerk/keyclerk/badge" alt="OpenSSF Scorecard"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-EUPL--1.2-blue" alt="Licence: EUPL-1.2"></a>
</p>

# KeyClerk

Access leases for Keycloak. KeyClerk receives people, checks who they are, and hands out keys that end by
themselves: for employees, contractors, visitors and partners, for applications, privileged roles and doors.

> Status: engine 0.26.1 (2026-10-25). The source is public; no package is released yet. It runs on one host for a demo
> and a local test stack; nobody else should run it in production yet. What follows separates what runs today, what exists as a tested library that nothing runs yet,
> and what is designed only. A claim moves up a column only with the code and a test.

## Why

Keycloak signs people in very well. It does not answer the governance questions around that: who asked for this
access, who approved it, until when, is it still needed, and is it really gone when it should be. Full identity
governance suites answer them, but they are large. KeyClerk is the small piece in between: grants as records, decided
by policy, applied by one writer, ending on time. What it does that such suites usually do not, and how each part is
meant to grow: [docs/what-sets-keyclerk-apart.md](docs/what-sets-keyclerk-apart.md).

## What runs today

- **Signed records.** Every grant, lease, group, delegation and approval is a record in one YAML document, checked
  against `keyclerk/schema/records.schema.json`. The desk writes it: each change becomes a new revision, signed with the
  desk's key, with its log line signed and hash-chained. History is append-only (`records.guard`): a revoked grant
  never comes back. A deployment may keep the document in git; KeyClerk does not require it and has no merge-request
  flow of its own. From 0.26.0 a deployment can choose the signed change log on SQLite instead (`store.kind: sqlite`,
  decision 0022): the desk proposes each change through the checking signer, which judges it and signs a checkpoint
  per change; personal data stays outside the log, which carries internal anchors only (decision 0028). A running
  YAML desk moves with `keyclerk.store.migrate` (docs/migrate-to-change-log.md).
- **Policy decides, in process.** The Rego in `keyclerk/policy/` is compiled to WebAssembly and evaluated in process
  (wasmtime); no OPA server runs. Some policies (`access.rego`, `delegation.rego`, `fallback.rego`) are still mirrored in
  Python and their Rego is only tested, not evaluated at run time.
- **One writer, per host.** The reconciler (`keyclerk.reconcile`) is the only component that changes Keycloak: it
  compares the records with the realm, adds what is due, removes what has ended, never touches a membership it did not
  create, and stops when a run would remove more than the configured cap. The writer lock is a local file: two
  deployments with their own state would both write (decision 0013 records the fix, not built).
- **State is derived.** Whether a grant is pending, active, ended or revoked is computed from the records and the clock
  (`keyclerk/access_state.py`). Clock skew can only narrow access.
- **The desk and its API** (`keyclerk.api`): people sign in at the broker and see what they hold and manage and why;
  deputies change groups, and each change is applied, held for a second key, or refused with its reasons. Approvals can
  be the approver's own signature at the broker (decision 0006). What that proof does not cover is written in
  `keyclerk/approvals.py`: a desk compromised while it serves its pages could show one change and have another signed.
  A high-risk change also carries its proposer's own signature, which the checking signer requires (decision 0015);
  a low-risk change's proposer is vouched for by the desk alone.
- **The read-only console** (`keyclerk.console`) and need-to-know views: the persona graph and the delegation tree.
- **Leases for externals:** lease records, lease groups, and generated Keycloak Workflow definitions for reminders and
  blocking (`keyclerk/leases.py`); the Workflows themselves run in Keycloak.
- **Visits** (decision 0009, 0010): person-first visits, QR codes and badges at the desk. Frozen since 2026-10-23 until
  the core is complete. A visit is its own file beside the records, vouched for by the signed log, and erased
  `visits.retention_days` (default 30) after it closes (decision 0009, amendment).
- **Personas** (decision 0011, 0011a change 1): daily and admin personas, workloads and agents; the persona rule is on
  `enforce` by default since 0.16.1 (set `identity.persona_rule: warn` to see the impact first).

- **Edges** (decision 0014): site appliances that enforce leases on a bastion while they may be cut off. The desk
  enrols them (the root with the security officer's key), cuts a signed bundle per edge inside the ceiling its officer
  signed, takes signed requests from the edge agent only (`keyclerk/edge.py`), relays ciphertexts to person keys that a
  passkey derives through WebAuthn PRF and that the desk cannot read (`keyclerk/relay.py`, `keyclerk/ui/personkey.js`),
  and acknowledges escrowed break-glass halves and evidence chains. The edge policy ships as compiled WebAssembly with a
  conformance set (`tests/conformance/edge.json`). The bundle key is still a file of its own; moving every granting key into the checking signer is decision 0021,
  not built. Since edge protocol 1.3 a bundle carries no e-mail address: an edge fetches it sealed when it needs it.

## Tested libraries that nothing runs yet

`keyclerk/apply_engine.py` (the highly available apply engine with leader leases and a reduction journal),
`keyclerk/events.py` (CloudEvents carrying OCSF, an outbox), `keyclerk/access_paths.py`, `keyclerk/keys.py`,
`keyclerk/pools.py` (access paths, custody, pools and fallback ladders), and `keyclerk/piam/` (physical access through a
PACS or OSDP). Each has unit tests; none is wired into the reconciler, the desk or the console.

## Designed, not built

- A separate confirmation page that shows the change before the approver signs (decision 0006).
- Proof of identity normalised into OpenID Identity Assurance, and trust per kind of proof.
- Privacy registry (purpose, legal basis, retention class per field), sealed proof copies, crypto-erasure.
- Reviews (event-driven and signed, not campaigns), dormancy, impact diffs in approvals, SoD exceptions, holder
  bounds, outliers, orphan accounts, agents bounded by their person, a witness and leaver proof (decision 0020); joiners,
  movers and leavers from HR (decision 0004).
- SIEM and SOAR interfaces, identity visibility and Shared Signals (0018 H4 to H6), off-site backup with restore drills
  and restore safety (0019), every granting key in the checking signer (0021).
- Many targets per deployment and one writer enforced by credential (decision 0013), persona history (0012), admin
  personas by plane changes 2 to 5 (0011a), invitations and access in hours (0010).
- For the signed change log (decision 0022, running since 0.26.0): PostgreSQL as a replica, signed snapshots, the
  witness co-signing the per-change checkpoints (0021).

How KeyClerk is kept secure, and how to report a problem privately: [SECURITY.md](SECURITY.md) and the threat model
([docs/threat-model.md](docs/threat-model.md)). Why it works as it does: the decision records in
[docs/decisions](docs/decisions); what changed in each release: [CHANGELOG.md](CHANGELOG.md); the standards it
implements and the projects it stands on: [docs/references.md](docs/references.md).

## Footprint

One image, three commands: `keyclerk.reconcile`, `keyclerk.console` and `keyclerk.api` (the desk). No database server; the desk
keeps its store on a volume: the YAML document, or the change log in one SQLite file. All state is files in the
desk's store and the signer's and the reconciler's state directories. The image is built from a tag with hash-locked dependencies.

Measured on 0.23.0 (2026-10-24, x86-64, the test fixture's 12 people):

| | Today | Minimal image (measured, not adopted) |
|---|---|---|
| Image, unpacked / compressed | 192 MB / 64 MB | 110 MB / 36 MB |
| Desk process ready, resident memory | 0.59 s, 80 MB | 0.49 s, 69 MB |
| Signer, reconciler resident memory | 28 MB, 31 MB | about the same |

Of the image, KeyClerk itself is under 3 MB; wasmtime (32 MB) and cryptography (16 MB) are the largest packages.
Size today: the engine checks are near linear since 0017 (`tools/bench_checks.py`: 1,000 extra people 4.4 s, 5,000 in
29 s; 136 s at 50 people before). On the YAML store the records are one document, loaded and signed whole on every
change. That fits up to about 1,000 people: at the desk (`tools/bench_desk.py`) a change takes 7 s at 200 extra people and 32 s at
1,000, a preview 9 s and 45 s, a desk start 8 s and 41 s; at 5,000 the document alone is 19 MB and takes about 25 s to
parse and validate. The signed change log on SQLite (decision 0022, from 0.26.0) is built for 500,000 identities:
at 20,000 employees a desk change takes about 3.4 s and a desk start 52 s (docs/testing/realistic-load.md).

## Configuration as code

The engine holds no rules of its own. Everything it applies comes from one configuration document that a deployment
keeps in its own repository, validated against `keyclerk/schema/config.schema.json`:

| Section | What it sets |
|---|---|
| `roles`, `grant_limits` | roles with plane and class, activation and functional lifetimes, subject kinds, scope levels |
| `external_access` | lease categories and their limits, reminders, retention |
| `delegation`, `attributes` | delegated administration of nested groups; the attribute registry with pedigree and freshness |
| `risk_port` | trust floors per risk class and the limits on risk acceptance |
| `situation` | what each situation level restricts, and what it may switch on |
| `places` | the kinds of physical place and how they nest |
| `access_paths`, `availability` | independent layers per label, scenarios, obligations; pools and fallback ladders |

```python
from keyclerk import config, delegation
config.configure("deployment/keyclerk.yaml")      # or set KEYCLERK_CONFIG
```

Records (grants, leases, groups, delegations, situations) follow `keyclerk/schema/records.schema.json`; trust from a
risk and trust source follows `keyclerk/schema/trust-input.schema.json`. The Rego in `keyclerk/policy/` reads its data
under `data.keyclerk`.

## Layout

```
keyclerk/          the engine (Python): records, grants, leases, delegation, places, situation levels, risk port,
                   the reconciler, the desk and console, connectors; libraries not yet wired in (see above)
keyclerk/schema/   configuration, records and trust-input schemas
keyclerk/policy/   the Rego that decides at the enforcement points, with its tests
tests/             unit tests on a neutral test tenant (tests/fixtures)
docs/decisions/    why the engine is built the way it is
```

Deployments, their configuration, their own policy packs and their examples live in their own repositories; a test
fails if this repository names one.

## Running

One image, three commands: the reconciler (the one writer of the broker's managed groups), the read-only console and
the desk (`keyclerk.api`). Build from a reviewed commit or a signed tag; the image installs only the hash-locked
`requirements.lock`.

```
git archive HEAD | podman build -t keyclerk:0.26.1 -   # or a signed release tag, once releases are published
podman run --read-only -v ./keyclerk.yaml:/etc/keyclerk/keyclerk.yaml:ro -v ./records.yaml:/etc/keyclerk/records.yaml:ro   -v ./records.yaml.sig:/etc/keyclerk/records.yaml.sig:ro -v ./records.pub:/etc/keyclerk/records.pub:ro   -v ./writer:/run/secrets/writer:ro -v ./reader:/run/secrets/reader:ro -v keyclerk-state:/var/lib/keyclerk keyclerk:0.26.1   keyclerk.reconcile --config /etc/keyclerk/keyclerk.yaml --records /etc/keyclerk/records.yaml   --signing-key /etc/keyclerk/records.pub --keycloak https://id.example --realm example   --secret-file /run/secrets/writer --reader-client keyclerk-reader --reader-secret-file /run/secrets/reader   --state /var/lib/keyclerk --apply
podman run --read-only -p 127.0.0.1:8090:8090 ... keyclerk:0.26.1 keyclerk.console --host 0.0.0.0   --allowed-host console.example --oidc-public-issuer https://id.example/realms/example   --oidc-redirect https://console.example/callback ...
```

Without `--apply` a run is a dry run. Records are applied only when they pass every check, carry a valid signature
(or the run says `--allow-unsigned`, for a local demo) and do not rewrite history; a run that would remove more than the
configured cap stops until an override names that exact plan.

Keycloak (26.8 and later) needs, per realm: SCIM switched on (`scimApiEnabled`); an admin-only user-profile attribute
`anchor` annotated `kc.scim.schema.attribute: externalId`, so people are found by their source's immutable id while
usernames stay human; a writer client (SCIM, `manage-users`), a reader client (`view-users`, `query-users`,
`query-groups`), both confidential with full scope off and the realm's SCIM base URL as an audience; a public console
client with PKCE and a `keyclerk-viewer` role for the people allowed to look.

## The desk and its API

`python -m keyclerk.api` serves the desk: people sign in at the broker and see what they hold and manage and why;
deputies add and remove members, nest groups, create subgroups and delegate, each change applied, held for a second
key, or refused by the engine with its reasons. Applied changes are signed: on the YAML store as record revisions, on the change log as links the checking signer
judges and signs; the reconciler applies either.

The front end in `keyclerk/ui` is only one client of the API. Build your own against `/api/v1` (contract:
`keyclerk/schema/api.openapi.json`, also served at `/api/v1/openapi.json`): a browser front end on the desk's own
origin uses the session and sends the CSRF token from `/api/v1/me` in `X-KeyClerk-CSRF`; any other front end
registers its own broker client, is named with `--api-client`, and sends its user's access token as a bearer token.
The broker must put the person's anchor in the token (an `anchor` claim). See decision 0005.

The contract is generated: change `tools/gen_api_contract.py`, run it, and commit both (a test holds them equal).
It explains itself (every change field and error code carries its meaning), and the bundled front end's API page is
built from it: every call, what it answers, how to call it from your own front end, reads tried with your own access,
changes previewed through `POST /changes/preview` (nothing applied, held or logged) and made only after a confirm.

Approvals can be the approver's own signature (decision 0006): with `approvals.proofs: required`, approving
means signing in again at the broker with the change's statement as the nonce; the reconciler verifies every proof
(pass `--approval-issuer` and `--approval-audience`) and refuses a revision with an approval nobody signed.

On Keycloak (decision 0007): give the writer fine-grained permissions for group membership only and set
`reconcile.logout_on_removal: false`; register `/backchannel-logout` as the back-channel logout URL of the desk's and
the console's clients; turn on admin events so manual changes are attributed; bind a passkey to an authentication level
and name it in `approvals.acr`; name clients that must use DPoP with `--dpop-client`.

Reads are need-to-know: a viewer and the root see everything; anyone else sees the groups they manage or belong to
(and the names above them), their own delegation chain and what is below it, and the changes they made, approved,
or that touch a group they manage or themselves. The directory and the reconciler's runs are for people who manage.
Writes are limited per person (30 in 10 minutes) and so are requests at once (4); both answer 429 `rate_limited`.
A change that needs several keys collects them one approval at a time (`approvals` on a pending change).

One desk process owns a store (a lock file). Every commit is written ahead and its log line is signed with the
desk's key; at start the desk repairs what a crash left (a cut log line, an unreadable pending file, an uncommitted
revision file, half-published records), only towards a revision a signed log line vouches for, and records what it
did in the log. Anything else stops it with a StoreFault: restore the store from a backup. A store written by 0.4.3 or
earlier has unsigned log lines and does not start: seed a new one.

On the signed change log (`store.kind: sqlite`, decision 0022) the desk holds no signing key: it runs with
`--signer unix:/run/keyclerk/signer.sock` (or `tcp:` with `--signer-token`), proposes every change to the checking
signer (`python -m keyclerk.signer --key ... --state ... --config ... --listen ...`), and follows the signer's log every
15 s. With the signer down, reads go on and writes are refused, never queued; readiness says why. A running YAML desk
moves with `python -m keyclerk.store.migrate`: the runbook, with the way back, is
[docs/migrate-to-change-log.md](docs/migrate-to-change-log.md).

## Health and metrics

Decision 0018 (H1 to H3). On the desk's own port, answered for any Host because an orchestrator probes by address:
`/healthz` says `ok` while the process serves; `/readyz` says `ready` (200) or `not ready` (503) and nothing more.
Ready means the store opens and its change log verifies, the policy modules load, the checking signer answers, and
the reconciler's last run started within `reconcile.ready_max_age_seconds` (default 900; only when `--broker-state` is
given). A broker that is down never makes the desk unready: it shows in the metrics. The answer is computed at most
every 5 seconds, however often it is asked.

The management listener is off unless `--mgmt-port` is given (default host 127.0.0.1), with its own bearer token from
`--mgmt-token-file` (at least 32 characters), read only. `/metrics` is Prometheus text, standard library only, from a
fixed list (`keyclerk/metrics.py`, each metric naming its alert or budget); labels come from fixed value lists, and no
person, group or edge id is ever a label. `/readyz` there gives each check with its reason. A push stack uses an
OpenTelemetry Collector that scrapes this page. The signer answers `{"op": "ping"}`; the reconciler's liveness is the
age of its last run.

## Developing

```
pip install -e ".[dev]"
git config core.hooksPath hooks      # the pre-push gate
pytest
opa test keyclerk/policy/
```

## Prior art and acknowledgements

KeyClerk did not start from a blank page. Before building it we searched GitHub, GitLab, npm and PyPI (about a
hundred queries, October 2026) and studied the projects below in depth. We borrowed ideas, not code.

- **[discord/access](https://github.com/discord/access)** (Apache-2.0). KeyClerk's access-request, owner-approval and
  expiring-access-review flows are informed by Discord's open-source Access: constraint tags with strictest-wins
  limits, derived grants that never outlive their source, approver sets computed from owners, the owner's review of
  expiring access, and a typed audit event list. KeyClerk differs by keeping grants in git, writing Keycloak through
  one reconciler and signing approvals.
- **[GoogleCloudPlatform/jit-groups](https://github.com/GoogleCloudPlatform/jit-groups)** (Apache-2.0). KeyClerk's
  policy shape (a hierarchy with inherited access lists, join and approve constraints, a mandatory expiry) and its
  split between joining, approving yourself and approving others follow ideas from Google Cloud's JIT Groups, as does
  re-evaluating policy at approval time. KeyClerk differs by deciding with OPA and keeping a record of every request
  and approval.
- **[aws-samples/iam-identity-center-team](https://github.com/aws-samples/iam-identity-center-team)** (MIT-0).
  KeyClerk's request lifecycle, the split between eligibility and approver policy, scheduled elevation, failing closed
  when no approver exists and linking session activity to the elevation window draw on AWS's TEAM for IAM Identity
  Center. KeyClerk derives these states from records and the clock instead of storing them in a workflow engine.

Thanks to the teams at Discord, Google Cloud and AWS for publishing clear designs. Also standing on the shoulders of:
[Keycloak](https://www.keycloak.org/), [Open Policy Agent](https://www.openpolicyagent.org/),
[keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli), [Keycloakify](https://www.keycloakify.dev/),
[OpenID Identity Assurance](https://openid.net/specs/openid-ida-verified-claims-1_0-final.html),
[midPoint](https://evolveum.com/midpoint/) (a full identity governance suite KeyClerk can work next to),
[libosdp](https://github.com/goToMain/libosdp) and [NATS](https://nats.io/). The closest earlier attempt we found,
[4nass/keycloak-access-requests](https://github.com/4nass/keycloak-access-requests), confirmed the need and the rule
that a governance tool never removes what it did not create.

## Licence

EUPL-1.2 (European Union Public Licence, version 1.2): see LICENSE and NOTICE.

## Security

Please report vulnerabilities privately as described in SECURITY.md, never in a public issue.
