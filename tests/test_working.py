"""Decision 0022 S4 (a): the working set. For random changes on a store, the reach through the store's refs index is
the reach over the whole records, and the scoped judgement on the working set is the scoped judgement on the whole
records, for the old state and the new. A miss prints the change."""
import copy
import random
from collections import Counter

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import clock, delegation, scope
from keyclerk import edge as E
from keyclerk.desk import _Dumper, _jsonable_records
from keyclerk.store import link as L
from keyclerk.store import migrate as M
from keyclerk.store import replay as RP
from keyclerk.store.link import StoreRefused
from keyclerk.store.memory import MemoryStore
from keyclerk.store.sqlite import SqliteStore
from keyclerk.store.working import StoreIx, working_doc
from test_scope import T, mutate, world

KEY = Ed25519PrivateKey.generate()
AT = "2026-10-24T12:00:00Z"
OUTCOMES: Counter = Counter()


@pytest.fixture(autouse=True)
def unbounded(monkeypatch):
    """The bound is a cost limit, not a rule: lifted here, so every change takes the working-set path when it can (a
    small test organisation passes 20% of its memberships at once). test_a_wide_working_set_falls_back holds it."""
    from keyclerk.store import working
    monkeypatch.setattr(working, "BOUND", 10.0)


def store_of(doc: dict, kind: str, tmp_path):
    raw = yaml.dump(_jsonable_records({**doc, "revision": 3}), Dumper=_Dumper, sort_keys=False, allow_unicode=False)
    s = MemoryStore(E.public_hex(KEY), doc["realm"]) if kind == "memory" else \
        SqliteStore(tmp_path / f"w-{random.random()}.db", E.public_hex(KEY), doc["realm"])
    M.migrate_yaml(raw, KEY.sign(raw.encode()).hex(), KEY, s, AT)
    return s


def scoped(doc, r):
    with clock.at(T):
        return sorted(scope.scoped_errors(doc, r))


def compare(snap, live, ops, what) -> list[str]:
    """Where the working-set path and the whole-records path disagree for one change: nothing, when they agree."""
    old_doc, new_doc = RP.records(snap), RP.records(live)
    by_docs = scope.reach(old_doc, new_doc, ops)
    by_store = scope.reach(StoreIx(snap), StoreIx(live), ops)
    if by_docs != by_store:
        if isinstance(by_store, scope.Full) and by_store.reason == "bound" and not isinstance(by_docs, scope.Full):
            OUTCOMES["bound"] += 1                         # the working set declines: judged in full, never wrong
            return []
        diff = by_docs ^ by_store if not isinstance(by_docs, scope.Full) and not isinstance(by_store, scope.Full) else None
        return [f"{what}: reach differs: {sorted(diff)[:8] if diff else (by_docs, by_store)}"]
    if isinstance(by_docs, scope.Full):
        OUTCOMES[by_docs.reason] += 1
        return []
    out = []
    for view, doc in ((snap, old_doc), (live, new_doc)):
        try:
            ws = working_doc(StoreIx(view), by_docs, doc.get("revision"))
        except scope.Wide:
            OUTCOMES["wide"] += 1
            return []
        a, b = scoped(ws, by_docs), scoped(doc, by_docs)
        if a != b:
            out.append(f"{what}: judged differently on the working set: only there {sorted(set(a) - set(b))[:4]}, "
                       f"missing there {sorted(set(b) - set(a))[:4]}")
    OUTCOMES["scoped"] += 1
    return out


def run_changes(s, doc, rnd, n) -> list[str]:
    misses = []
    for _ in range(n):
        new, ops, what = mutate(doc, rnd)
        if not ops:
            continue
        snap = s.snapshot()
        try:
            h = s.head()
            try:
                s.append(L.seal_link(KEY, s.realm, s.size(), h.hex(), 1, AT, ops, {"action": "test"}))
            except (StoreRefused, TypeError):
                continue
            if RP.apply_ops(RP.records(snap), {"change": {"ops": ops}}, s) != RP.records(s):
                misses.append(f"{what}: apply_ops differs from the records after the link")
            misses += compare(snap, s, ops, what)
            doc = new
        finally:
            snap.close()
    return misses


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
@pytest.mark.parametrize("persona", ["enforce", "off"])
@pytest.mark.parametrize("seed", range(3))
def test_the_working_set_path_is_the_whole_records_path(seed, persona, kind, monkeypatch, tmp_path):
    real = delegation.identity_rules
    monkeypatch.setattr(delegation, "identity_rules", lambda: {**real(), "persona_rule": persona})
    rnd = random.Random(4000 + seed)
    doc = world(rnd.choice([0, 4, 12]), rnd)
    s = store_of(doc, kind, tmp_path)
    try:
        assert run_changes(s, copy.deepcopy(doc), rnd, 15) == []
    finally:
        s.close()


def _with(doc, kind, s, tmp_path, ops):
    """compare() for one change of the store built from doc."""
    snap = s.snapshot()
    try:
        s.append(L.seal_link(KEY, s.realm, s.size(), s.head().hex(), 1, AT, ops, {"action": "test"}))
        before = OUTCOMES["scoped"]
        misses = compare(snap, s, ops, f"{kind}: {ops[0]['op']} {ops[0]['kind']} {ops[0]['key']}")
        assert OUTCOMES["scoped"] == before + 1, dict(OUTCOMES)      # judged on the working set, not a fallback
        return misses
    finally:
        snap.close()


def _put(kind, rec):
    rec = M._json(rec)
    return {"op": "put", "kind": kind, "key": L.record_key(kind, rec), "record": rec}


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_an_error_two_delegations_below_the_touched_one_is_judged_alike(kind, tmp_path):
    rnd = random.Random(11)
    doc = world(4, rnd)
    d0 = next(d for d in doc["delegations"] if d["parent"] == "root")
    d1 = {**copy.deepcopy(d0), "delegation_id": "D-example-0101", "parent": d0["delegation_id"], "by": d0["delegate"]}
    d2 = {**copy.deepcopy(d1), "delegation_id": "D-example-0102", "parent": "D-example-0101"}
    m = next(x for x in doc["memberships"] if "anchor" in x["member"])
    deep = {**copy.deepcopy(m), "membership_id": "M-example-0102", "under": "D-example-0102", "by": d2["delegate"]}
    doc["delegations"] += [d1, d2]
    doc["memberships"].append(deep)
    s = store_of(doc, kind, tmp_path)
    try:
        shorter = {**M._json(d0), "end": M._json(d0["start"])}
        assert _with(doc, kind, s, tmp_path, [_put("delegations", shorter)]) == []
        r = scope.reach(StoreIx(s), StoreIx(s), [_put("delegations", shorter)])
        assert "M-example-0102" in r                       # two hops below the touched delegation
    finally:
        s.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_an_agents_directors_membership_and_a_change_that_reaches_nearly_nothing_are_judged_alike(kind, tmp_path):
    rnd = random.Random(12)
    doc = world(4, rnd)
    agent = next(p for p in doc["persons"] if p["kind"] == "agent")
    tpl = next(m for m in doc["memberships"] if m["membership_id"] == "M-example-9001")
    doc["memberships"].append({**copy.deepcopy(tpl), "membership_id": "M-example-9101",
                               "member": {"anchor": agent["director"]}})
    s = store_of(doc, kind, tmp_path)
    try:
        assert _with(doc, kind, s, tmp_path, [{"op": "del", "kind": "memberships", "key": "M-example-9101"}]) == []
        proof = L.proof_record({"records": ["M-example-9001"], "by": agent["director"], "token": "t"})
        assert _with(doc, kind, s, tmp_path, [_put("approval_proofs", proof)]) == []
    finally:
        s.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_a_person_taking_an_anchor_another_person_lists_is_judged_alike(kind, tmp_path):
    """The engine has no error for one anchor on two persons; what changes is which person the anchor belongs to (the
    first listing it). The working set loads every person listing a loaded anchor, so it maps the anchor as the whole
    records do, even when that other person is otherwise outside it."""
    rnd = random.Random(13)
    doc = world(12, rnd)
    a, b = doc["persons"][2], doc["persons"][-3]
    s = store_of(doc, kind, tmp_path)
    try:
        taken = {**M._json(b), "anchors": [a["anchors"][0]] + list(b["anchors"])}
        assert _with(doc, kind, s, tmp_path, [_put("persons", taken)]) == []
        r = scope.reach(StoreIx(s), StoreIx(s), [_put("persons", taken)])
        if not isinstance(r, scope.Full):
            try:
                ws = working_doc(StoreIx(s), r, None)
                assert {a["person"], b["person"]} <= {p["person"] for p in ws["persons"]}
            except scope.Wide:
                pass
    finally:
        s.close()


def test_a_wide_working_set_falls_back(monkeypatch, tmp_path):
    from keyclerk.store import working
    monkeypatch.setattr(working, "BOUND", 0.0001)
    rnd = random.Random(14)
    doc = world(30, rnd)
    s = store_of(doc, "memory", tmp_path)
    m = next(x for x in doc["memberships"] if "anchor" in x["member"])
    r = scope.reach(StoreIx(s), StoreIx(s), [_put("memberships", m)])
    with pytest.raises(scope.Wide):
        working_doc(StoreIx(s), r, None)
