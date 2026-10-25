"""Decision 0022 S4, the key test: reach soundness. On generated organisations (with an approver, a suspension, an
agent, includes, a rule membership, delegation chains and revocations), apply a random change: an edit, a delete, a
copy, a new revocation or suspension. Judge the old and the new state at one moment. Every subject whose errors
differ must be inside the reach the engine computed from the change, or the change must have fallen back to the
full check. A miss fails with the change printed. Both persona modes."""
import copy
import json
import random
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from keyclerk import clock, delegation, scope
from keyclerk.reconcile import check_records
from keyclerk.store import link as L

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
T = datetime(2026, 11, 2, 9, 30, tzinfo=timezone.utc)
FALLBACKS: Counter = Counter()


def world(n: int, rnd: random.Random) -> dict:
    """bench_checks' organisation plus what the fixture lacks: an approver, a suspension, an agent with a membership,
    a rule membership, an include, a second-level delegation."""
    from bench_checks import organisation
    doc = organisation(n)
    t0 = min(m["start"] for m in doc["memberships"])
    root = doc["root"]["holders"][0]["anchor"]
    officer = doc["root"]["officer"]
    tenants = [p for p in doc["persons"] if p["kind"] == "tenant" and root not in p["anchors"]]
    doc.setdefault("approvers", []).append({"approver_id": "A-example-0001", "anchor": tenants[0]["anchors"][0],
                                            "appointed_by": root, "approved_by": [officer], "from": t0,
                                            "to": t0 + timedelta(days=200)})
    some = rnd.choice([m for m in doc["memberships"] if "anchor" in m["member"]])
    doc["suspensions"] = [{"suspension_id": "S-example-0001", "anchor": some["member"]["anchor"], "at": t0, "by": root}]
    doc["persons"].append({"person": "agent-1", "kind": "agent", "anchors": ["agent:0001"],
                           "owner": tenants[0]["anchors"][0], "director": tenants[0]["anchors"][0]})
    low = [m for m in doc["memberships"] if "anchor" in m["member"]
           and doc_groups(doc).get(m["group"], {}).get("max_risk") == "low"]
    tpl = low[0] if low else doc["memberships"][0]
    doc["memberships"].append({**copy.deepcopy(tpl), "membership_id": "M-example-9001", "member": {"anchor": "agent:0001"}})
    doc["memberships"].append({**copy.deepcopy(tpl), "membership_id": "M-example-9002",
                               "member": {"rule": {"attribute": "role", "values": ["x"], "source": "Keycloak",
                                                   "max_age_hours": 24}}})
    others = [g for g in doc["groups"] if g["max_risk"] == "low" and g["group_id"] != tpl["group"] and g.get("parent")]
    if others:
        doc["memberships"].append({**copy.deepcopy(tpl), "membership_id": "M-example-9003",
                                   "member": {"group": others[0]["group_id"]}})
    return doc


def doc_groups(doc):
    return {g["group_id"]: g for g in doc.get("groups", [])}


FIELDS = {
    "memberships": ["group", "member", "by", "under", "start", "end", "approved_by", "standby_from"],
    "delegations": ["parent", "group", "delegate", "by", "max_risk", "powers", "depth_left", "start", "end",
                    "approved_by", "max_membership_days"],
    "persons": ["kind", "anchors", "unit", "director", "owner", "personas"],
    "groups": ["max_risk", "carries", "parent"],
    "approvers": ["anchor", "from", "to", "approved_by", "appointed_by"],
    "admin_revocations": ["mode", "at", "from", "id"],
    "suspensions": ["anchor", "at"],
    "leases": ["anchor", "end", "sponsor"],
    "grants": ["role", "end", "approved_by"],
}


def pool(doc: dict, kind: str, field: str) -> list:
    vals = [r[field] for r in doc.get(kind, []) if field in r]
    if field in ("by", "delegate", "anchor", "appointed_by", "director", "owner"):
        vals += [a for p in doc["persons"] for a in p["anchors"]]
    if field == "member":
        vals += [{"anchor": a} for p in doc["persons"][:20] for a in p["anchors"]] + [{"group": g} for g in doc_groups(doc)]
    if field == "under":
        vals += list(doc_groups(doc)) [:0] + ["root"] + [d["delegation_id"] for d in doc.get("delegations", [])]
    if field == "id":
        vals += [d["delegation_id"] for d in doc.get("delegations", [])] + [m["membership_id"] for m in doc["memberships"]]
    if field == "mode":
        vals += ["revoke", "retire"]
    return vals


def mutate(doc: dict, rnd: random.Random) -> tuple[dict, list[dict], str]:
    new = copy.deepcopy(doc)
    what = rnd.choice(["edit", "edit", "edit", "delete", "copy", "revoke", "suspend"])
    if what == "revoke":
        target = rnd.choice([d["delegation_id"] for d in new["delegations"]] + [m["membership_id"] for m in new["memberships"]]
                            + [a["approver_id"] for a in new.get("approvers", [])])
        rec = {"id": target, "at": rnd.choice([m["start"] for m in new["memberships"]]) + timedelta(days=rnd.randint(0, 30)),
               "by": rnd.choice(pool(new, "memberships", "by")), "mode": rnd.choice(["revoke", "retire"])}
        new.setdefault("admin_revocations", []).append(rec)
        return new, [put("admin_revocations", rec)], f"add admin revocation {rec}"
    if what == "suspend":
        rec = {"suspension_id": f"S-example-{rnd.randint(100, 999)}", "anchor": rnd.choice(pool(new, "memberships", "by")),
               "at": rnd.choice([m["start"] for m in new["memberships"]]), "by": new["root"]["holders"][0]["anchor"]}
        new.setdefault("suspensions", []).append(rec)
        return new, [put("suspensions", rec)], f"add suspension {rec}"
    kind = rnd.choice([k for k in FIELDS if new.get(k)])
    i = rnd.randrange(len(new[kind]))
    rec = new[kind][i]
    if what == "delete":
        del new[kind][i]
        return new, [{"op": "del", "kind": kind, "key": L.record_key(kind, _json(rec))}], f"delete {kind} {L.record_key(kind, _json(rec))}"
    if what == "copy":
        rec = copy.deepcopy(rec)
        field = R_IDS[kind]
        rec[field] = f"{rec[field]}-copy{rnd.randint(1, 99)}" if kind != "admin_revocations" else rec[field]
        if kind == "admin_revocations":
            rec["mode"] = "revoke" if rec["mode"] == "retire" else "retire"
        new[kind].append(rec)
        return new, [put(kind, rec)], f"copy into {kind} {json.dumps(_json(rec))[:300]}"
    field = rnd.choice(FIELDS[kind])
    values = pool(new, kind, field)
    if not values:
        return new, [], "nothing"
    old_key = L.record_key(kind, _json(rec))
    rec[field] = copy.deepcopy(rnd.choice(values))
    ops = [put(kind, rec)]
    if L.record_key(kind, _json(rec)) != old_key:
        ops.append({"op": "del", "kind": kind, "key": old_key})
    return new, ops, f"edit {kind} {old_key}: {field} = {json.dumps(_json(rec.get(field)))[:200]}"


R_IDS = {"memberships": "membership_id", "delegations": "delegation_id", "persons": "person", "groups": "group_id",
         "approvers": "approver_id", "admin_revocations": "id", "suspensions": "suspension_id", "leases": "lease_id",
         "grants": "grant_id"}


def _json(x):
    return json.loads(json.dumps(x, default=str))


def put(kind, rec):
    return {"op": "put", "kind": kind, "key": L.record_key(kind, _json(rec)), "record": _json(rec)}


def by_subject(doc: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    with clock.at(T):
        errs = check_records(doc)
    for e in errs:
        s = scope.subject_of(e, doc)
        assert " " not in s and s != "schema", f"an error no subject owns: {e}"   # a new message format: map it
        out.setdefault(s, set()).add(e.removesuffix(" (now)"))
    return out


@pytest.mark.parametrize("persona", ["enforce", "off"])
@pytest.mark.parametrize("seed", range(4))
def test_every_subject_whose_errors_change_is_inside_the_reach(seed, persona, monkeypatch):
    real = delegation.identity_rules
    monkeypatch.setattr(delegation, "identity_rules", lambda: {**real(), "persona_rule": persona})
    rnd = random.Random(seed * 7 + (persona == "off"))
    doc = world(rnd.choice([0, 4, 12]), rnd)
    before = by_subject(doc)
    misses = []
    for _ in range(20):                                   # cumulative: each change applies to the last state
        new, ops, what = mutate(doc, rnd)
        if not ops:
            continue
        r = scope.reach(doc, new, ops)
        after = by_subject(new)
        if isinstance(r, scope.Full):
            FALLBACKS[r.reason] += 1
        else:
            FALLBACKS["scoped"] += 1
            changed = {s for s in set(before) | set(after) if before.get(s) != after.get(s)}
            missed = sorted(s for s in changed if not scope.covered(s, r))
            if missed:
                misses.append(f"{what}\n  missed {missed}: before {[before.get(s) for s in missed]} after "
                              f"{[after.get(s) for s in missed]}")
        if r != scope.Full("schema"):                     # a schema error would make every later change full
            doc, before = new, after
    assert misses == [], "\n".join(misses)


def test_deleting_a_delegation_a_person_an_include_and_an_approver_is_reached():
    rnd = random.Random(99)
    doc = world(4, rnd)
    before = by_subject(doc)
    for kind, pick in (("delegations", lambda d: d["delegations"][0]),
                       ("persons", lambda d: next(p for p in d["persons"] if p["kind"] == "tenant" and not set(p["anchors"])
                                                  & {d["root"]["officer"], d["root"]["holders"][0]["anchor"]})),
                       ("memberships", lambda d: next(m for m in d["memberships"] if "group" in m["member"])),
                       ("approvers", lambda d: d["approvers"][0])):
        new = copy.deepcopy(doc)
        rec = pick(new)
        new[kind].remove(rec)
        ops = [{"op": "del", "kind": kind, "key": L.record_key(kind, _json(rec))}]
        r = scope.reach(doc, new, ops)
        assert not isinstance(r, scope.Full), kind
        after = by_subject(new)
        changed = {s for s in set(before) | set(after) if before.get(s) != after.get(s)}
        assert all(scope.covered(s, r) for s in changed), (kind, sorted(s for s in changed if not scope.covered(s, r)))


def test_what_reaches_everyone_falls_back_to_the_full_check():
    rnd = random.Random(5)
    doc = world(0, rnd)
    new = copy.deepcopy(doc)
    g = next(g for g in new["groups"] if g.get("parent"))
    g["parent"] = next(x["group_id"] for x in new["groups"] if x["group_id"] not in (g["group_id"], g["parent"]))
    assert scope.reach(doc, new, [put("groups", g)]) == scope.Full("group_tree")
    assert scope.reach(doc, doc, [put("sod", doc["sod"][0])]) == scope.Full("sod")
    assert scope.reach(doc, doc, [{"op": "put", "kind": "head", "key": "root", "record": {"value": {}}}]) == scope.Full("head")
    bad = {**_json(doc["memberships"][0]), "end": "not a time"}
    assert scope.reach(doc, doc, [{"op": "put", "kind": "memberships", "key": bad["membership_id"], "record": bad}]) \
        == scope.Full("schema")


# --- the scoped judgement equals the full one -------------------------------------------------------------------------

def _full(doc):
    with clock.at(T):
        return check_records(doc)


def _scoped(doc, reach):
    with clock.at(T):
        return scope.scoped_errors(doc, reach)


def _subjects(doc) -> list[str]:
    ids = [str(r.get(f)) for k, f in scope.R.KINDS.items() for r in doc.get(k, []) if isinstance(r, dict)]
    ids += [p["person"] for p in doc.get("persons", [])] + [g["group_id"] for g in doc.get("groups", [])]
    anchors = {a for p in doc.get("persons", []) for a in p["anchors"]}
    anchors |= {m["member"]["anchor"] for m in doc.get("memberships", []) if "anchor" in m["member"]}
    return ids + [f"sod:{a}" for a in sorted(anchors)] + ["tree", "places"]


@pytest.mark.parametrize("persona", ["enforce", "off"])
@pytest.mark.parametrize("seed", range(3))
def test_scoped_judging_is_the_full_check_kept_to_the_reach(seed, persona, monkeypatch):
    real = delegation.identity_rules
    monkeypatch.setattr(delegation, "identity_rules", lambda: {**real(), "persona_rule": persona})
    rnd = random.Random(300 + seed)
    doc = world(rnd.choice([0, 4, 12]), rnd)
    for _ in range(6):                                    # some errors to keep or drop: a few random changes first
        new, ops, _ = mutate(doc, rnd)
        if ops and scope.reach(doc, new, ops) != scope.Full("schema"):
            doc = new
    full = _full(doc)
    everything = set(_subjects(doc)) | {"rate:*", "subtree:*", "adminrev:*", "sod:*"}
    assert sorted(_scoped(doc, everything)) == sorted(full)
    subjects = _subjects(doc)
    for _ in range(8):
        reach = set(rnd.sample(subjects, rnd.randint(1, max(1, len(subjects) // 3))))
        if rnd.random() < 0.3:
            reach |= {"rate:*", "subtree:*"}
        want = sorted(e for e in full if scope.covered(scope.subject_of(e, doc), reach))
        assert sorted(_scoped(doc, reach)) == want, sorted(reach)[:20]


@pytest.mark.parametrize("persona", ["enforce", "off"])
@pytest.mark.parametrize("seed", range(3))
def test_a_change_judged_scoped_finds_exactly_the_new_errors_the_full_check_finds(seed, persona, monkeypatch):
    from keyclerk.signer import _norm
    real = delegation.identity_rules
    monkeypatch.setattr(delegation, "identity_rules", lambda: {**real(), "persona_rule": persona})
    rnd = random.Random(700 + seed)
    doc = world(rnd.choice([0, 4, 12]), rnd)
    judged = 0
    for _ in range(15):
        new, ops, what = mutate(doc, rnd)
        if not ops:
            continue
        r = scope.reach(doc, new, ops)
        if isinstance(r, scope.Full):
            if r != scope.Full("schema"):
                doc = new
            continue
        judged += 1
        full_fresh = _norm(_full(new)) - _norm(_full(doc))
        scoped_fresh = _norm(_scoped(new, r) + scope.touched_schema_errors(new, ops)) - _norm(_scoped(doc, r))
        assert scoped_fresh == full_fresh, what
        doc = new
    assert judged


@pytest.mark.parametrize("n", [0, 12])
def test_the_checks_answer_the_same_on_the_replicas_strings_as_on_yaml_datetimes(n, tmp_path):
    """Decision 0022 S4 point 4: records read back from the log carry times as UTC text, records parsed from YAML carry
    datetimes; the engine's checks give the same answer on both, so the working set hands them on unconverted."""
    import yaml
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from keyclerk import edge as E
    from keyclerk import records
    from keyclerk.desk import _Dumper, _jsonable_records
    from keyclerk.store import migrate as M
    from keyclerk.store import replay as RP
    from keyclerk.store.memory import MemoryStore
    rnd = random.Random(n)
    doc = world(n, rnd)
    for _ in range(8):                                    # with some errors in it
        new, ops, _ = mutate(doc, rnd)
        if ops and scope.reach(doc, new, ops) != scope.Full("schema"):
            doc = new
    key = Ed25519PrivateKey.generate()
    raw = yaml.dump(_jsonable_records({**doc, "revision": 3}), Dumper=_Dumper, sort_keys=False, allow_unicode=False)
    store = MemoryStore(E.public_hex(key), doc["realm"])
    M.migrate_yaml(raw, key.sign(raw.encode()).hex(), key, store, "2026-10-24T12:00:00Z")
    rows = [r for _, r in store.side_scan("anchor_map")]       # the replica speaks internal anchors (decision 0028)
    assert sorted(_full(RP.records(store))) == sorted(_full(M.rekeyed(records.loads(raw), rows)))


@pytest.mark.parametrize("seed", range(4))
def test_the_scoped_history_guard_is_records_guard(seed):
    """The guard over the touched records (and what they bring along) answers exactly as the guard over everything."""
    from keyclerk import records
    rnd = random.Random(900 + seed)
    doc = world(rnd.choice([0, 4, 12]), rnd)
    doc["revocations"] = doc.get("revocations") or []
    seen = 0
    for _ in range(40):
        new, ops, what = mutate(doc, rnd)
        if not ops:
            continue
        assert scope.guard_errors(doc, new, ops) == records.guard(doc, new), what
        seen += bool(records.guard(doc, new))
        doc = new if rnd.random() < 0.5 else doc
    assert seen                                           # some changes did rewrite history


@pytest.mark.parametrize("same_day", [True, False])
def test_a_membership_judged_scoped_meets_the_subtree_cap_of_its_own_day(same_day, monkeypatch):
    """A membership is counted in its subtree's bucket for the day it starts: a change reaches that day's bucket (old
    and new start), never every day of the subtree, so one big organisation under one top delegation stays scoped. At
    the cap, a widening on the same day is refused scoped exactly as in full; on another day it is not."""
    from keyclerk.signer import _norm
    doc = world(12, random.Random(5))
    under = [m for m in doc["memberships"] if m["under"] not in ("root",) and "anchor" in m["member"]]
    tpl = under[0]
    day = delegation._ts(tpl["start"]).date()
    top = delegation._top(doc, tpl["under"])
    acts = [m for m in doc["memberships"] if m["under"] != "root" and delegation._top(doc, m["under"]) == top
            and delegation._ts(m["start"]).date() == day]
    acts += [d for d in doc["delegations"] if d["parent"] != "root" and delegation._top(doc, d["parent"]) == top
             and delegation._ts(d["start"]).date() == day]
    section = delegation.R._get()                                                    # the live configuration's dict
    monkeypatch.setitem(section, "widenings_per_subtree_per_day", len(acts))         # the bucket is exactly full
    monkeypatch.setitem(section, "widenings_per_deputy_per_day", 10_000)
    start = delegation._ts(tpl["start"]) + (timedelta(minutes=1) if same_day else timedelta(days=1))
    rec = {**copy.deepcopy(tpl), "membership_id": "M-example-9100", "start": start}
    new = {**doc, "memberships": doc["memberships"] + [rec]}
    ops = [{"op": "put", "kind": "memberships", "key": rec["membership_id"], "record": rec}]
    r = scope.reach(doc, new, ops)
    assert not isinstance(r, scope.Full), r
    assert not any(s.startswith("subtree:") and s.endswith(":*") for s in r)            # no all-days bucket
    full_fresh = _norm(_full(new)) - _norm(_full(doc))
    scoped_fresh = _norm(_scoped(new, r)) - _norm(_scoped(doc, r))
    assert scoped_fresh == full_fresh
    capped = [e for e in full_fresh if e.startswith(f"subtree of {top}")]
    assert bool(capped) == same_day, full_fresh
