# SPDX-License-Identifier: EUPL-1.2
"""Decision 0028 point 1: records.ANCHOR_PATHS is the one table of where a record names a person by anchor. The schema
cannot grow an anchor-like field the table misses, and in real records every anchor value sits at a path in the table."""
import json
import re
import sys
from pathlib import Path

import yaml

from keyclerk import anchors as A
from keyclerk import records

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "keyclerk/schema/records.schema.json").read_text(encoding="utf-8"))
ANCHOR_LIKE = re.compile(r"anchor|^by$|_by$|officer|owner|director|delegate|sponsor|checker|person|holders|custodians"
                         r"|approvers|^host|hosts|organiser|escort|steward|deputy|front_office|coordinator|issued_by|contact|on_call")
# Fields whose names look like anchors but hold something else, each with why.
NOT_ANCHORS = {
    "persons.person": "the person's record name (a label; moved into the mapping table by the migration, step 3)",
    "edges.officer_key": "the officer's public key, not a person's anchor",
    "edge_rotations.officer_key": "the officer's public key, not a person's anchor",
    "situations.review_by": "a time (when the situation is reviewed), not an anchor",
    "places.hosts[]": "machine host names at a place (graph.py maps hosts to places for access paths), not people",
    "visits.delegation.contact": "free text naming a visiting delegation's contact: personal data in the erasable visit "
                                 "side record, stripped with the other free text (decision 0028 point 7), not an anchor",
}


def _resolve(node):
    while isinstance(node, dict) and "$ref" in node:
        node = SCHEMA["$defs"][node["$ref"].split("/")[-1]]
    return node


def _string_fields(node, path: str, seen=()):
    """(path, name) of every string-valued field under a schema node, in ANCHOR_PATHS' path syntax."""
    node = _resolve(node)
    if not isinstance(node, dict) or id(node) in seen:
        return
    seen = seen + (id(node),)
    for alt in node.get("anyOf", []) + node.get("oneOf", []) + node.get("allOf", []):
        yield from _string_fields(alt, path, seen)
    if node.get("type") == "array" or "items" in node:
        yield from _string_fields(node.get("items", {}), path + "[]", seen)
    for name, sub in (node.get("properties") or {}).items():
        sub_r = _resolve(sub)
        p = f"{path}.{name}" if path else name
        types = sub_r.get("type")
        if types == "string" or (isinstance(types, list) and "string" in types):
            yield p, name
        if types == "array":
            items = _resolve(sub_r.get("items", {}))
            if items.get("type") == "string":
                yield p + "[]", name
        yield from _string_fields(sub, p, seen)


def _candidates():
    for kind, node in SCHEMA["properties"].items():
        node = _resolve(node)
        target = node.get("items", node) if node.get("type") == "array" else node
        for path, name in _string_fields(target, ""):
            if ANCHOR_LIKE.search(name):
                yield kind, path.lstrip(".").replace("[].", "[].")


def test_every_anchor_like_schema_field_is_in_the_table():
    missing = []
    for kind, path in _candidates():
        if path in records.ANCHOR_PATHS.get(kind, ()) or f"{kind}.{path}" in NOT_ANCHORS:
            continue
        missing.append(f"{kind}.{path}")
    assert not missing, ("anchor-like schema fields neither in records.ANCHOR_PATHS nor in NOT_ANCHORS: "
                         + ", ".join(sorted(set(missing))))


def test_the_table_names_only_fields_the_schema_has():
    have = {(k, p) for k, p in _candidates()}
    stale = [f"{k}.{p}" for k, paths in records.ANCHOR_PATHS.items() for p in paths
             if k in SCHEMA["properties"] and (k, p) not in have]
    assert not stale, "records.ANCHOR_PATHS names paths the schema does not have: " + ", ".join(stale)


def _organisation():
    sys.path.insert(0, str(ROOT / "tools"))
    from bench_checks import organisation
    return organisation(30)


def _anchors_in(doc: dict) -> set[str]:
    out = {a for p in doc.get("persons", []) for a in p.get("anchors", [])}
    out |= {h["anchor"] for h in (doc.get("root") or {}).get("holders", [])}
    out |= {x["anchor"] for x in doc.get("leases", []) if isinstance(x.get("anchor"), str)}
    return out


def _values(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _values(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for v in node:
            yield from _values(v, path + "[]")
    elif isinstance(node, str):
        yield path, node


def test_in_real_records_every_anchor_sits_at_a_table_path():
    for doc in (yaml.safe_load((ROOT / "tests/fixtures/records.yaml").read_text(encoding="utf-8")), _organisation()):
        anchors = _anchors_in(doc)
        assert anchors
        stray = []
        for kind, value in doc.items():
            recs = [value] if isinstance(value, dict) else value if isinstance(value, list) else []
            for rec in recs:
                if not isinstance(rec, dict):
                    continue
                listed = set(records.anchor_values(kind, rec))
                for path, v in _values(rec):
                    if v in anchors and (path, v) not in listed:
                        stray.append(f"{kind}.{path}={v}")
        assert not stray, "anchors outside records.ANCHOR_PATHS: " + ", ".join(sorted(set(stray))[:20])


def test_anchor_values_reads_nested_lists_and_objects():
    rec = {"holders": [{"anchor": "a1", "appointed_by": "a2"}], "officer": "a3"}
    assert sorted(records.anchor_values("root", rec)) == [("holders[].anchor", "a1"), ("holders[].appointed_by", "a2"),
                                                          ("officer", "a3")]
    assert list(records.anchor_values("suspensions", {"lifted": {"by": ["x", "y"]}})) == [("lifted.by[]", "x"),
                                                                                          ("lifted.by[]", "y")]
    assert list(records.anchor_values("memberships", {"member": {"group": "g"}})) == []


def test_in_real_records_every_value_at_a_table_path_is_a_persons_anchor():
    """The other direction: the table names no field that holds something else (a host name re-keyed as if it were a
    person would break the access-path graph after the migration). Anchors are provider-prefixed (idp:, op:, ext:,
    agent:, spiffe:); a feed: source is a feed, never re-keyed (anchors.NOT_PERSONS); a bare word is a host or a name."""
    for doc in (yaml.safe_load((ROOT / "tests/fixtures/records.yaml").read_text(encoding="utf-8")), _organisation()):
        anchors = _anchors_in(doc)
        foreign = []
        for kind, value in doc.items():
            recs = [value] if isinstance(value, dict) else value if isinstance(value, list) else []
            for rec in recs:
                if isinstance(rec, dict):
                    foreign += [f"{kind}.{p}={v}" for p, v in records.anchor_values(kind, rec)
                                if v not in anchors and A.is_person(v) and ":" not in v]
        assert not foreign, "values at ANCHOR_PATHS that are no person's anchor: " + ", ".join(sorted(set(foreign))[:20])

