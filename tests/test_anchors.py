# SPDX-License-Identifier: EUPL-1.2
"""Decision 0028 point 1: internal anchors. rekey() rewrites every anchor the records hold and leaves none behind; a
mapping row is checkable against the log's commitment; the mapping lives only in erasable side tables."""
import sys
from pathlib import Path

import pytest
import yaml

from keyclerk import anchors as A
from keyclerk import records

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = yaml.safe_load((ROOT / "tests/fixtures/records.yaml").read_text(encoding="utf-8"))


def _organisation():
    sys.path.insert(0, str(ROOT / "tools"))
    from bench_checks import organisation
    return organisation(12)


def _every_anchor(doc):
    return {v for kind in records.ANCHOR_PATHS for rec in (
        [doc[kind]] if isinstance(doc.get(kind), dict) else doc.get(kind) or [])
        if isinstance(rec, dict) for _, v in records.anchor_values(kind, rec)}


def _amap(doc):
    return {a: A.new() for a in sorted(_every_anchor(doc))}


@pytest.mark.parametrize("doc", [FIXTURE, _organisation()], ids=["fixture", "organisation"])
def test_rekey_rewrites_every_anchor_and_leaves_none_behind(doc):
    import copy
    before = copy.deepcopy(doc)
    amap = _amap(doc)
    out = A.rekey(doc, amap)
    left = _every_anchor(out)
    assert left and all(A.is_internal(a) for a in left)
    assert left == set(amap.values()) & left                    # only the mapped anchors appear
    assert A.unmapped(out, {}) == []
    assert doc == before                                       # the input is not changed


def test_rekey_refuses_an_anchor_without_a_mapping():
    amap = _amap(FIXTURE)
    missing = sorted(amap)[0]
    amap.pop(missing)
    with pytest.raises(A.Unmapped, match="no internal anchor"):
        A.rekey(FIXTURE, amap)
    assert any(x.endswith("=" + missing) for x in A.unmapped(FIXTURE, amap))


def test_rekey_is_reversible_with_the_inverse_map():
    amap = _amap(FIXTURE)
    back = {v: k for k, v in amap.items()}
    out = A.rekey(FIXTURE, amap)
    assert A.rekey(out, back) == FIXTURE


def test_a_mapping_row_is_checked_against_its_commitment():
    row = A.mapping_row("4f2c-idp-subject", label="ann")
    good = A.commitment(row["salt"], row["idp"])
    assert A.COMMIT.fullmatch(good) and A.is_internal(row["anchor"])
    assert A.row_matches(row, [good])
    assert not A.row_matches({**row, "idp": "someone-else"}, [good])          # a re-pointed row is caught
    assert not A.row_matches({**row, "salt": "00" * 16}, [good])
    assert not A.row_matches({"anchor": row["anchor"]}, [good])               # a row without its fields


def test_anchors_are_random_and_never_repeat():
    seen = {A.new() for _ in range(2000)}
    assert len(seen) == 2000 and all(A.is_internal(a) for a in seen)
    assert not A.is_internal("idp:7c1f-ann") and not A.is_internal("kc:short")


def test_the_mapping_side_tables_are_erasable_kinds_outside_the_log():
    from keyclerk.store import check_side, link, StoreRefused
    assert {"anchor_map", "anchor_idp"} <= set(link.SIDE_KINDS)
    assert "anchor_map" not in link.LOG_KINDS and "anchor_idp" not in link.LOG_KINDS
    row = A.mapping_row("4f2c-idp-subject")
    check_side("anchor_map", row["anchor"], row)
    check_side("anchor_idp", A.idp_key(row["idp"]), {"anchor": row["anchor"]})
    with pytest.raises(StoreRefused):
        check_side("anchor_map", A.new(), row)                                  # filed under another anchor
    with pytest.raises(StoreRefused):
        check_side("anchor_map", row["anchor"], {**row, "anchor": "idp:7c1f"})  # not internal
    with pytest.raises(StoreRefused):
        check_side("anchor_idp", "x" * 64, {"anchor": row["anchor"], "idp": row["idp"]})   # the id never in the reverse row


def test_the_schema_takes_commitments_in_accounts_records_only():
    good = {**FIXTURE, "accounts": [{"anchor": "kc:" + "0" * 32, "commit": "sha256:" + "a" * 64}]}
    assert not [e for e in records.validate(good) if "accounts" in e]
    for bad in ({"anchor": "idp:7c1f-ann", "commit": "sha256:" + "a" * 64}, {"anchor": "kc:" + "0" * 32, "commit": "md5:abc"},
                {"anchor": "kc:" + "0" * 32}):
        assert [e for e in records.validate({**FIXTURE, "accounts": [bad]}) if "accounts" in e], bad
    person = {**FIXTURE["persons"][0], "commits": ["sha256:" + "a" * 64]}
    assert [e for e in records.validate({**FIXTURE, "persons": [person] + FIXTURE["persons"][1:]}) if "commits" in e]


# --- two phases from the legacy anchor claim to the broker subject (decision 0028) --------------------------------

def _store_with(*rows):
    from keyclerk.store.memory import MemoryStore
    s = MemoryStore("00" * 32, "example")
    for r in rows:
        s.side_put("anchor_map", r["anchor"], r)
        s.side_put("anchor_idp", A.idp_key(r["idp"]), {"anchor": r["anchor"]})
        if r.get("sub"):
            s.side_put("anchor_idp", A.sub_key(r["sub"]), {"anchor": r["anchor"]})
    return s


def test_an_unlinked_row_accepts_the_legacy_anchor_claim():
    row = A.mapping_row("idp:7c1f-ann")
    s = _store_with(row)
    assert A.resolve(s, {"anchor": "idp:7c1f-ann", "sub": "u-1"}) == row["anchor"]
    assert A.resolve(s, {"anchor": "idp:nobody"}) is None and A.resolve(s, {}) is None


def test_a_linked_row_accepts_only_its_subject():
    row = {**A.mapping_row("idp:7c1f-ann"), "sub": "u-ann"}
    s = _store_with(row)
    assert A.resolve(s, {"sub": "u-ann"}) == row["anchor"]                            # by subject, no claim needed
    assert A.resolve(s, {"anchor": "idp:7c1f-ann", "sub": "u-ann"}) == row["anchor"]
    assert A.resolve(s, {"anchor": "idp:7c1f-ann", "sub": "u-mallory"}) is None      # the attribute moved or copied
    assert A.resolve(s, {"anchor": "idp:7c1f-ann"}) is None                          # a linked row needs its subject


def test_the_verifier_checks_a_proof_through_the_mapping():
    from test_approvals import AUD, ISS, Broker
    from keyclerk import approvals
    from keyclerk import guard
    broker = Broker()
    row = {**A.mapping_row("idp:7c1f-ann"), "sub": "u-ann"}
    s = _store_with(row)
    proofs = approvals.BrokerProofs({ISS}, {AUD}, 300, "https://id.test/x", None, fetch=broker.jwks)
    proofs.resolve = lambda claims: A.resolve(s, claims)
    assert proofs(broker.token("n1", "idp:7c1f-ann", sub="u-ann"), "n1", row["anchor"])
    with pytest.raises(guard.InputRejected, match="someone else"):
        proofs(broker.token("n1", "idp:7c1f-ann", sub="u-mallory"), "n1", row["anchor"])
    with pytest.raises(guard.InputRejected, match="someone else"):
        proofs(broker.token("n1", "idp:7c1f-ann", sub="u-ann"), "n1", "idp:7c1f-ann")   # by must be internal
