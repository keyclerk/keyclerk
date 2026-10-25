"""The working set (decision 0022 S4): a change judged on the records it needs, in today's dict shape, so no check is
rewritten.

StoreIx is reach's index over a store (keyclerk.scope.Ix): the small kinds whole, each under a measured bound, the
large ones (persons, memberships, grants, revocations, leases) through the store's refs index. reach over it is the
reach over the whole records (tests/test_working.py).

working_doc(ix, reach) is the sub-document judging the reached subjects reads, built from what the check code reads
(keyclerk.delegation, grants, leases, edge_records, situation), in the replica's order (by key):
  - head fields and the small kinds whole;
  - memberships: the reached ones, every membership of every anchor whose separation of duty is reached and of
    the directors of their agents, every include and rule membership, every membership of the actor of each
    include in the reach (judging an include reads whether its actor is in the group it takes in), the records of every rate bucket in the reach;
    and, as facts, the records each judged membership's approvers made (reciprocity) and the memberships an
    administrative revocation in the reach names;
  - persons: every person listing an anchor any loaded record names (all of them, so the first one listing an
    anchor is the engine's), and the owners and directors of those;
  - leases of every such anchor (an anchor with a lease is external to the identity checks), with the grants,
    revocations and leases a reached grant or lease is judged with;
  - proofs whole, with their tokens.
A reach the working set cannot serve within BOUND of the memberships (a wildcard bucket, a very large group)
raises scope.Wide: the change is judged in full. The background full check compares this path with the full one.
"""
from __future__ import annotations

from keyclerk import scope
from keyclerk.store import link as L
from keyclerk.store import refs_of

KIND_BOUND = {"groups": 20_000, "catalogue": 20_000, "sod": 2_000, "delegations": 50_000, "admin_revocations": 200_000,
              "approvers": 20_000, "places": 20_000, "zones": 20_000, "org_units": 20_000, "situations": 20_000,
              "surge_packages": 2_000, "surge_grants": 20_000, "suspensions": 100_000, "edges": 20_000,
              "person_keys": 200_000, "edge_rotations": 20_000, "edge_visit_leases": 20_000,
              "approval_proofs": 500_000, "proposal_proofs": 500_000}
BOUND = 0.2                                    # of the memberships: a larger working set is judged in full


class StoreIx(scope.Ix):
    def __init__(self, view):
        self.view = view
        self._small: dict[str, list[dict]] = {}
        self._recs: dict[tuple[str, str], dict | None] = {}
        super().__init__()

    def small(self, kind: str) -> list[dict]:
        if kind in scope.VISIT_KINDS:
            return []                            # visits live on the desk's side, never in the replica
        if kind not in self._small:
            if self.view.count(kind) > KIND_BOUND.get(kind, 20_000):
                raise scope.Wide(f"{kind} above its bound")
            self._small[kind] = [r for _, r in self.view.scan(kind)]
        return self._small[kind]

    def head(self, field: str):
        rec = self.view.get("head", field)
        return rec["value"] if rec else None

    def where(self, kind: str, field: str, values) -> list[dict]:
        values = [v for v in values if isinstance(v, str)]
        if not values:
            return []
        if kind in scope.SMALL_KINDS:
            want = {(field, v) for v in values}
            return [r for r in self.small(kind) if set(refs_of(kind, r)) & want]
        keys = self.view.find(kind, field, values)
        missing = [k for k in keys if (kind, k) not in self._recs]
        if missing:                              # one statement per 500 keys, not one per record
            got = self.view.get_many(kind, missing)
            for k in missing:
                self._recs[(kind, k)] = got.get(k)
        return [r for r in (self._recs[(kind, k)] for k in keys) if r is not None]

    def mems_both(self, f1: str, v1, f2: str, v2) -> list[dict]:
        """Both conditions through the index first (keys intersected), so only the records that meet both are fetched."""
        v1, v2 = [v for v in v1 if isinstance(v, str)], [v for v in v2 if isinstance(v, str)]
        if not v1 or not v2:
            return []
        keys = sorted(set(self.view.find("memberships", f1, v1)) & set(self.view.find("memberships", f2, v2)))
        missing = [k for k in keys if ("memberships", k) not in self._recs]
        if missing:
            got = self.view.get_many("memberships", missing)
            for k in missing:
                self._recs[("memberships", k)] = got.get(k)
        return [r for r in (self._recs[("memberships", k)] for k in keys) if r is not None]

    def get(self, kind: str, key: str):
        if kind in scope.VISIT_KINDS:
            return None
        if (kind, key) not in self._recs:
            self._recs[(kind, key)] = self.view.get(kind, key)
        return self._recs[(kind, key)]


def scoped_judgement(old_view, view, ops: list[dict], revision: int):
    """What a change reaches, judged on the two states (decision 0022 S4): (old working records, new working records,
    the reach), or scope.Full with the reason when the change reaches everyone or its working set is too wide. The
    checking signer and the desk on the change log judge by it alike."""
    old_ix, new_ix = StoreIx(old_view), StoreIx(view)
    r = scope.reach(old_ix, new_ix, ops)
    if isinstance(r, scope.Full):
        return r
    try:
        return working_doc(old_ix, r, revision), working_doc(new_ix, r, revision + 1), r
    except scope.Wide:
        return scope.Full("bound")


def fresh_errors(old: dict, new: dict, reach: set[str], ops: list[dict]) -> set[str]:
    """The engine errors a change adds within its reach: after, with the touched records' schema, less before."""
    def norm(errs):
        return {e.removesuffix(" (now)") for e in errs}
    return norm(scope.scoped_errors(new, reach) + scope.touched_schema_errors(new, ops)) - norm(
        scope.scoped_errors(old, reach))


def working_doc(ix: StoreIx, reach: set[str], revision: int | None) -> dict:
    """The records judging the subjects in reach reads (see the module docstring), in today's shape."""
    from keyclerk import records as R
    from keyclerk.store import replay as RP
    if any(s in ("rate:*", "subtree:*") for s in reach):
        raise scope.Wide("a whole rate family")
    view = ix.view
    doc: dict = {}
    for f in L.HEAD_FIELDS:
        v = ix.head(f)
        if v is not None:
            doc[f] = v
    for kind in scope.SMALL_KINDS:
        if kind in scope.VISIT_KINDS:
            continue
        recs = ix.small(kind)
        if recs:
            doc[kind] = recs
    mems: dict[str, dict] = {}
    ix.stats = {}                                # memberships each stage adds: why a working set is wide

    def take(recs):
        for m in recs:
            mems.setdefault(m["membership_id"], m)

    def stage(name):
        ix.stats[name] = len(mems) - sum(ix.stats.values())

    for s in reach:                              # reached memberships, and what an administrative revocation names
        m = ix.get("memberships", s.removeprefix("adminrev:")) if ":" not in s or s.startswith("adminrev:") else None
        if m is not None:
            take([m])
    stage("reached")
    take(ix.includes())
    take(ix.rule_mems())
    stage("includes and rules")
    sod = {s[4:] for s in reach if s.startswith("sod:") and s != "sod:*"}
    if "sod:*" in reach:
        raise scope.Wide("separation of duty for everyone")
    holders = set().union(*(ix.anchors_of(a) for a in sod)) if sod else set()
    holders |= ix.agents_of(holders)
    for p in ix.where("persons", "anchors", holders):               # agents reach no further than their directors
        for a in (p.get("director"), p.get("owner")):
            if a:
                holders |= ix.anchors_of(a)
    take(ix.mems("member.anchor", holders))
    stage("separation of duty holders")
    # a reached include reads the group it takes in at one place: whether its actor is among that group's members
    # (delegation._include_errors), so the actor's memberships (and their agents') are what it needs, not the group's
    actors: set[str] = set()
    for m in list(mems.values()):
        if "group" in m["member"] and m["membership_id"] in reach:
            actors |= ix.anchors_of(m["by"])
    actors |= ix.agents_of(actors)
    take(ix.mems("member.anchor", actors))
    holders |= actors
    stage("include actors")
    for s in reach:                              # rate buckets: every record counted in them
        parts = s.split(":")
        if parts[0] == "rate" and len(parts) >= 3:
            anchors = _anchors_of_person(ix, ":".join(parts[1:-1]))       # rate:<person>:<day>
            day = parts[-1]
            take(m for m in ix.mems("by", anchors) if day == "*" or str(m["start"])[:10] == day)
        elif parts[0] == "subtree" and len(parts) >= 3:
            top, day = ":".join(parts[1:-1]), parts[-1]
            under = ({top} | ix.descendants(top)) if top != "root" else set()
            take(m for m in ix.mems("under", under) if day == "*" or str(m["start"])[:10] == day)
    stage("rate buckets")
    judged = [m for m in mems.values() if m["membership_id"] in reach or m["member"].get("anchor") in holders]
    # reciprocity (delegation._reciprocal_days): for a record by X approved by Y, only what Y made with X among its
    # approvers is read; so per actor X, the records by X's approvers whose approved_by names X
    by_actor: dict[str, set[str]] = {}
    for r in judged + [d for d in ix.dels.values() if d["delegation_id"] in reach]:
        if r.get("by") and r.get("approved_by"):
            by_actor.setdefault(r["by"], set()).update(a for a in r["approved_by"] if a)
    facts = []
    for actor, approvers in sorted(by_actor.items()):
        approver_anchors = set().union(*(ix.anchors_of(a) for a in approvers))
        facts += ix.mems_both("by", approver_anchors, "approved_by", ix.anchors_of(actor))
    ix.stats["reciprocity facts"] = len({m["membership_id"] for m in facts} - set(mems))
    if len(mems) + len(facts) > BOUND * max(1, view.count("memberships")) and view.count("memberships") > 50:
        raise scope.Wide("memberships above the bound")
    take(facts)
    doc["memberships"] = [mems[k] for k in sorted(mems)]
    _people(ix, doc, reach)
    _grants_leases(ix, doc, reach)
    for kind in R.KINDS:
        if kind not in doc and kind in R.KINDS and kind not in R.OPTIONAL:
            doc[kind] = []
    doc.setdefault("suspensions", [])
    for kind in L.PROOF_KINDS:
        recs = [RP._token(view, p) for p in ix.small(kind)] if kind in KIND_BOUND else []
        if recs:
            doc[kind] = recs
    if revision is not None:
        doc["revision"] = revision
    return doc


def _anchors_of_person(ix: StoreIx, person: str) -> set[str]:
    p = ix.get("persons", person)
    return set(p.get("anchors", [])) | {person} if p else {person}


def _people(ix: StoreIx, doc: dict, reach: set[str]) -> None:
    """Every person listing an anchor any loaded record names, the owners and directors of those, and the leases of
    each such anchor (a lease makes its holder external to the identity checks)."""
    anchors: set[str] = set()
    for recs in doc.values():
        if isinstance(recs, list):
            for r in recs:
                if isinstance(r, dict):
                    anchors |= scope._people_fields(r)
    root = doc.get("root") or {}
    anchors |= {h.get("anchor") for h in root.get("holders", [])} | {root.get("officer")}
    anchors |= {c.get("by") for g in doc.get("groups", []) for c in g.get("carries", [])}
    anchors |= {e.get("owner") for e in doc.get("catalogue", [])}
    for r in doc.get("admin_revocations", []):
        if isinstance(r.get("id"), str) and r["id"].startswith("root:"):
            anchors.add(r["id"][5:])
    anchors.discard(None)
    persons = {p["person"]: p for p in ix.where("persons", "anchors", anchors)}
    for s in reach:                              # reached persons by their id
        p = ix.get("persons", s)
        if p is not None:
            persons.setdefault(p["person"], p)
    more = set()
    for p in list(persons.values()):
        more |= {a for a in (p.get("owner"), p.get("director")) if a}
        more |= set(p.get("anchors", []))
    for p in ix.where("persons", "anchors", more - anchors):
        persons.setdefault(p["person"], p)
    for p in ix.where("persons", "owner", set().union(*(set(p.get("anchors", [])) for p in persons.values())) if persons
                      else set()) + ix.where("persons", "director", set().union(*(set(p.get("anchors", []))
                                                                                   for p in persons.values())) if persons else set()):
        persons.setdefault(p["person"], p)
    doc["persons"] = [persons[k] for k in sorted(persons)]
    every = anchors | more | {a for p in persons.values() for a in p.get("anchors", [])}
    doc["_lease_anchors"] = every


def _grants_leases(ix: StoreIx, doc: dict, reach: set[str]) -> None:
    every = doc.pop("_lease_anchors", set())
    leases = {ls["lease_id"]: ls for ls in ix.where("leases", "anchor", every)}
    grants: dict[str, dict] = {}
    for s in reach:
        g = ix.get("grants", s)
        if g is not None:
            grants[g["grant_id"]] = g
        ls = ix.get("leases", s)
        if ls is not None:
            leases[ls["lease_id"]] = ls
    for g in list(grants.values()):              # eligibility for an activation: the subject's grants
        for x in ix.where("grants", "subject.anchor", [g["subject"].get("anchor")]):
            grants.setdefault(x["grant_id"], x)
    for ls in list(leases.values()):             # one lease per person at a time, totals: the identity's leases
        if ls.get("identity_hash"):
            for x in ix.where("leases", "identity_hash", [ls["identity_hash"]]):
                leases.setdefault(x["lease_id"], x)
    for x in ix.where("grants", "lease", list(leases)):
        grants.setdefault(x["grant_id"], x)
    for g in list(grants.values()):
        if g.get("lease"):
            ls = ix.get("leases", g["lease"])
            if ls is not None:
                leases.setdefault(ls["lease_id"], ls)
    revs = {r["grant_id"]: r for r in ix.where("revocations", "grant_id", list(grants) + [s for s in reach])}
    doc["grants"] = [grants[k] for k in sorted(grants)]
    doc["revocations"] = [revs[k] for k in sorted(revs)]
    if leases:
        doc["leases"] = [leases[k] for k in sorted(leases)]
    else:
        doc.pop("leases", None)
