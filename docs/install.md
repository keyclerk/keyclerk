# First run

A fresh KeyClerk install has no records, and nothing can be done from the desk without them. No desk action writes the
catalogue of entitlements, the realm's head (who holds the root role, who the security officer is) or the people the
records know, and creating a group at the desk needs a parent group that already exists. So the first records are
written outside the desk, once. `keyclerk init` writes that minimum, checks it with the engine's own checks and hands
it to the desk, which signs it as the first revision.

Init only bootstraps the first administrators. Every other person comes from the source of joiners (the identity
provider and the joiner feed the deployment connects), never from init.

## What init writes, and why

| Record | What it holds | Why it is needed |
|---|---|---|
| `realm.yaml`: `realm`, `home` | the realm's name and the home that masters its grants | every record belongs to one realm; the loader needs both |
| `realm.yaml`: `root` | the root trust owner (the first holder, from now on) and the security officer | the root is where every delegation starts; the security officer's key is the second key on the root's privileged changes, so the two are different people |
| `realm.yaml`: `persons` | the root, the security officer, optionally an edge officer and the entitlement's owner, each with their identity-provider anchor; when the top group is privileged, each anchor also states the persona purpose `admin` | the desk lets only a person the records know act; nobody can add the first person from inside. Power over a privileged group, and membership in it, take an admin persona (the persona rule, enforced by default) |
| `catalogue/<entitlement>.yaml` | one entitlement: its application, risk class (low, elevated, privileged) and owner | a group can carry only what is in the catalogue, set by the entitlement's owner |
| `groups/<group>.yaml` | one top group (no parent) carrying that entitlement, with its fixed class | the tree has exactly one top group, and every group the desk creates hangs under an existing one |
| `seed.yaml` | the same records as one file | the form the desk seeds from and signs; the reconciler reads one signed file, never a directory |

The directory form (one file per record) is the form to review and keep in a repository; `seed.yaml` carries the same
records as one file. Init reads both back through the loader and refuses if they differ.

Init refuses, with the reason and what completes the intent, when:

- the target directory is not empty (init never overwrites records; a realm that has records is changed at the desk);
- the root and the security officer are the same anchor;
- the edge officer is the root or the security officer (an edge's officer is never a core administrator, or a core
  administrator could widen an edge's ceiling);
- any value is not in the form the records take (anchors and identifiers in the narrow identifier set, a risk class
  from the three);
- the engine's checks refuse the result (the same checks the desk, the checking signer and the reconciler run: the
  records schema, identifiers, zoned times, duplicate ids, grants and the delegation tree). A top group whose fixed
  class is below the entitlement it carries is one example.

When it refuses, it writes nothing: the records are built and checked in a work directory next to the target and moved
into place only when every check passes.

## Running it

In a terminal, init asks for every value it is not given:

```
python -m keyclerk.init ./records --config keyclerk.yaml
```

For a scripted install, give every value as a flag and `--no-input`, so a missing value is refused instead of asked
for. None of the values is a secret: init holds no key and signs nothing.

```
python -m keyclerk.init ./records --config keyclerk.yaml --no-input \
    --realm example \
    --root idp:7c1f-root \
    --officer idp:31ee-officer \
    --entitlement admin-console --application keyclerk --risk privileged \
    --group all
```

| Flag | Value | Default |
|---|---|---|
| `--realm` | the realm's name: lowercase letters, digits and hyphens | asked |
| `--home` | the home that masters the realm's grants | the realm's name |
| `--root` | the root trust owner's anchor at the identity provider | asked |
| `--officer` | the security officer's anchor, another person than the root | asked |
| `--entitlement`, `--application` | the first entitlement and its application | asked |
| `--risk` | its class: low, elevated or privileged | asked |
| `--owner` | the entitlement's owner (the only one who may let a group carry it) | the root |
| `--group` | the top group's id: 2 to 63 lowercase letters, digits and hyphens | asked |
| `--group-risk` | the top group's fixed class | the entitlement's class |
| `--edge-officer` | an edge officer's anchor, never the root or the security officer | none |
| `--root-person`, `--officer-person`, `--edge-officer-person`, `--owner-person` | the person names in the records | `root-holder`, `security-officer`, `edge-officer`, `entitlement-owner` |

The configuration (`--config`, or `KEYCLERK_CONFIG` in the environment) is the one the desk will run with: the checks
read their roles and limits from it.

## After init

1. Review the records in the target directory. They are the realm's first revision.
2. Start the desk on an empty store with `--seed records/seed.yaml`. With `--signer` the checking signer signs the
   first revision; with `--signing-key` the desk signs it with the key in its own process (for development). The desk
   writes `records.yaml` and its detached signature `records.yaml.sig` as revision 1, the form the reconciler verifies
   with `--signing-key`. Unsigned records are never applied outside a local demo.
3. Sign in at the desk as the root trust owner and build the tree under the top group: subgroups, delegations, members.
4. Connect the source of joiners. People come from there; init is not run again for them.

From 0.25.0, the checking signer judges the first revision in full against an empty state, as it judges every later
change, and a seed that fails is refused with nothing signed. Before 0.25.0, the check init ran is what stands for the
first revision: seed the desk only from records that init (or the same checks) accepted.

When approval proofs are required (`approvals.proofs: required`), a seed's high-risk records need their proposer's own
proof, as every high-risk change does: the root signs the seed at the identity provider with a fresh sign-in, through
the desk's approval flow, before the first revision applies.

## Where the desk keeps the records
The desk keeps the records in the folder `--store` names. The configuration's `store` section chooses how: `kind:
yaml`, the signed YAML store and the default when the section is left out, or `kind: sqlite`, the signed change log
(decision 0022), from 0.26.0. On the change log the desk never holds the records key: start it with `--signer`.
docs/migrate-to-change-log.md moves a running deployment over; a new deployment on the change log starts the signer
empty and seeds it from `--seed`, its first change judged whole. The YAML store suits up to a few thousand people; the
change log is built for organisations of tens of thousands.

## Admin accounts for privileged groups
On a privileged top group, init writes each first administrator's anchor with the persona purpose `admin`, so the
root can act on the group and add people to it from the start. The better practice, and the point of the persona
rule, is a separate admin account per person: their daily account (mail, the web) never holds privileged rights. When
those accounts exist at the identity provider, give each person both anchors, the daily one with purpose `daily` and
the admin one with purpose `admin`, and sign in with the admin account for privileged work:

```yaml
- {person: root-holder, kind: tenant, anchors: ["idp:7c1f-root", "idp:7c1f-root-admin"],
   personas: [{anchor: "idp:7c1f-root", purpose: daily}, {anchor: "idp:7c1f-root-admin", purpose: admin}]}
```

Everyone added to a privileged group later needs an admin persona the same way; without one the desk refuses the
membership and says so.

## Seeding with your own tooling

A deployment that writes its records with its own tooling needs the same minimum. As one file, the form the desk
seeds from:

```yaml
realm: example
home: example
root:
  officer: "idp:31ee-officer"
  holders:
    - {anchor: "idp:7c1f-root", appointed_by: "keyclerk-init", from: "2026-10-01T00:00:00Z"}
persons:
  - {person: root-holder, kind: tenant, anchors: ["idp:7c1f-root"]}
  - {person: security-officer, kind: tenant, anchors: ["idp:31ee-officer"]}
grants: []
revocations: []
catalogue:
  - {entitlement: admin-console, application: keyclerk, risk: privileged, owner: "idp:7c1f-root"}
groups:
  - {group_id: all, parent: null, max_risk: privileged, carries: [{entitlement: admin-console, by: "idp:7c1f-root"}]}
```

What the checks require of it:

- `realm`, `grants` and `revocations` are always present (the lists may be empty); `home` is a string.
- `root.holders` has at least one holder with `anchor`, `appointed_by` and `from` (a time with a zone); `root.officer`
  is the security officer's anchor, a different person from the root.
- Every person has `person`, `kind` (tenant, external, agent or workload) and at least one anchor. The first
  administrators are `tenant`.
- Every catalogue entry has `entitlement`, `application`, `risk` and `owner`.
- There is exactly one group with `parent: null`. A group carries only catalogue entries, each set `by` the entry's
  owner, and nothing above its fixed `max_risk`.
- An anchor is an identifier from the narrow set (letters, digits and `._:@/+-`, no spaces) and never starts with
  `uid:`.

To check records written by other tooling with the same checks as init, load them and run the engine's check:

```
python -c "from keyclerk import config, records; from keyclerk.reconcile import check_records; \
config.configure('keyclerk.yaml'); print(check_records(records.load('records')) or 'accepted')"
```

The one-file-per-record form splits from the single file with `python -m keyclerk.records split seed.yaml records/`.
