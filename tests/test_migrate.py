"""Decision 0022 S2: from the signed YAML store to the change log and back. The genesis verifies the last YAML
revision's signature, not only its hash; links 1 to k migrate and nothing else does (no bulk path); at link k the state
equals the signed YAML by meaning, or the migration fails as a whole; export gives the YAML back, equal by meaning."""
import base64
import copy
import random
import sys
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import edge as E
from keyclerk import records as R
from keyclerk.desk import Store as DeskStore, _Dumper, _jsonable_records
from keyclerk.store import link as L, migrate as M, open_store, replay as RP
from keyclerk.store.link import StoreRefused

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "records.yaml"
KEY = Ed25519PrivateKey.generate()
PUB = E.public_hex(KEY)
AT = "2026-10-24T12:00:00Z"
TOKEN = "eyJ.a-broker-token.sig"


def signed(doc: dict, revision: int = 7, key=KEY) -> tuple[str, str]:
    """A YAML revision as the desk writes and signs it."""
    raw = yaml.dump(_jsonable_records({**doc, "revision": revision}), Dumper=_Dumper, sort_keys=False, allow_unicode=False)
    return raw, key.sign(raw.encode("utf-8")).hex()


def fixture() -> dict:
    return R.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(params=["memory", "sqlite"])
def url(request, tmp_path):
    return "memory:" if request.param == "memory" else f"sqlite:{tmp_path / 'store.db'}"


def migrated(url, doc=None, revision=7, visits=None):
    doc = doc or fixture()
    raw, sig = signed(doc, revision)
    s = open_store(url, PUB, doc["realm"])
    got = M.migrate_yaml(raw, sig, KEY, s, AT, visits)
    return s, raw, got


def as_logged(s, doc: dict) -> dict:
    """A records document as the store's log carries it: re-keyed by the store's own mapping rows (decision 0028)."""
    return M.rekeyed(doc, [r for _, r in s.side_scan("anchor_map")])


def nxt(s, ops, **over):
    h = s.head()
    return L.seal_link(KEY, s.realm, s.size(), h.hex(), 1, AT, ops, {"action": "test"}, **over)


# --- round trip -------------------------------------------------------------------------------------------------------

def test_the_fixture_migrates_and_exports_back_equal_by_meaning(url):
    s, raw, got = migrated(url)
    assert got["migration"] == s.migration() == "proven"
    assert got["revision"] == 7 and got["links"] == s.size() >= 2
    back = R.loads(M.export(s))
    assert M.meaning(back) == M.meaning(as_logged(s, R.loads(raw))) and back["revision"] == 7
    assert M.export(s) == M.export(s)                       # deterministic
    assert L.open_checkpoint(s.checkpoint(), PUB)["size"] == s.size()   # closed by a checkpoint at k+1
    s.close()


@pytest.mark.parametrize("seed", range(4))
def test_generated_organisations_round_trip(tmp_path, seed):
    """Property: any valid organisation, its lists in any order, migrates and exports back equal by meaning."""
    sys.path.insert(0, str(ROOT / "tools"))
    from bench_checks import organisation
    rnd = random.Random(seed)
    doc = organisation(rnd.choice([0, 3, 25, 60]))
    for v in doc.values():
        if isinstance(v, list):
            rnd.shuffle(v)
    for url in ("memory:", f"sqlite:{tmp_path / f'org-{seed}.db'}"):
        s, raw, got = migrated(url, copy.deepcopy(doc), revision=rnd.randint(1, 900))
        assert got["migration"] == "proven"
        assert M.meaning(R.loads(M.export(s))) == M.meaning(as_logged(s, R.loads(raw)))
        s.close()


# --- revisions ----------------------------------------------------------------------------------------------------------

def test_revisions_continue_and_the_migration_is_not_k_changes(url):
    s, _, _ = migrated(url, revision=41)
    k = s.size() - 1
    assert k >= 1 and RP.records(s)["revision"] == 41      # genesis and every migrate link show the YAML revision
    s.append(nxt(s, [{"op": "put", "kind": "groups", "key": "g-new", "record": {"group_id": "g-new"}}]))
    assert RP.records(s)["revision"] == 42                  # the first change after them is the next revision
    s.close()


# --- guards: no bulk path around approvals ------------------------------------------------------------------------------------------

def _genesis_and_parts(doc=None, revision=7, sig=None, drop=0):
    doc = doc or fixture()
    raw, good = signed(doc, revision)
    head, ops, side = M.split(doc)
    parts = M._parts(ops[drop:])
    import hashlib
    sha = hashlib.sha256(raw.encode()).hexdigest()
    g = L.seal_link(KEY, doc["realm"], 0, L.ZERO, 1, AT, head, {"action": "migrated"},
                    yaml={"revision": revision, "sha256": sha, "signature": sig or good, "parts": len(parts)})
    return raw, sha, side, g, parts


def _start(url, raw, sha, side, g):
    s = open_store(url, PUB, "example")
    s.side_put("genesis_yaml", sha, {"text": raw})
    for kind, items in side.items():
        for k, rec in items:
            s.side_put(kind, k, rec)
    s.append(g)
    return s


def test_nothing_but_the_migration_comes_before_link_k(url):
    raw, sha, side, g, parts = _genesis_and_parts()
    s = _start(url, raw, sha, side, g)
    with pytest.raises(StoreRefused, match="still migrating"):
        s.append(nxt(s, [{"op": "put", "kind": "groups", "key": "g-x", "record": {"group_id": "g-x"}}]))
    with pytest.raises(StoreRefused, match="still migrating"):
        s.append(nxt(s, parts[0], migrate={"part": 1, "parts": len(parts) + 1}))
    with pytest.raises(StoreRefused, match="part = seq"):
        nxt(s, parts[0], migrate={"part": 2, "parts": len(parts)})
    with pytest.raises(StoreRefused, match="only puts"):
        L.seal_link(KEY, "example", 1, "00" * 32, 1, AT, [{"op": "del", "kind": "groups", "key": "g"}], {},
                    migrate={"part": 1, "parts": 1})
    for i, p in enumerate(parts, 1):
        s.append(nxt(s, p, migrate={"part": i, "parts": len(parts)}))
    with pytest.raises(StoreRefused, match="the migration ended"):
        s.append(nxt(s, [{"op": "put", "kind": "groups", "key": "g-x", "record": {"group_id": "g-x"}}],
                     migrate={"part": len(parts) + 1, "parts": len(parts) + 1}))
    assert s.migration() == "proven"
    s.close()


def test_link_k_is_refused_unless_the_state_equals_the_signed_yaml(url):
    raw, sha, side, g, parts = _genesis_and_parts(drop=1)            # one record left out of the migration
    s = _start(url, raw, sha, side, g)
    for i, p in enumerate(parts[:-1], 1):
        s.append(nxt(s, p, migrate={"part": i, "parts": len(parts)}))
    before = (s.size(), s.root(), RP.records(s))
    with pytest.raises(StoreRefused, match="differ from the signed YAML revision"):
        s.append(nxt(s, parts[-1], migrate={"part": len(parts), "parts": len(parts)}))
    assert (s.size(), s.root(), RP.records(s)) == before and s.migration() is None
    with pytest.raises(StoreRefused, match="still migrating"):                       # and it can never take a change
        s.append(nxt(s, [{"op": "put", "kind": "groups", "key": "g-x", "record": {"group_id": "g-x"}}]))
    s.close()


def test_a_yaml_signature_by_another_key_is_refused(url):
    raw, sig = signed(fixture())
    s = open_store(url, PUB, "example")
    with pytest.raises(StoreRefused, match="does not verify against the records key"):
        M.migrate_yaml(raw, Ed25519PrivateKey.generate().sign(raw.encode()).hex(), KEY, s, AT)
    raw, sha, side, g, parts = _genesis_and_parts(sig=Ed25519PrivateKey.generate().sign(b"x").hex())
    s2 = _start(url.replace("store.db", "store2.db"), raw, sha, side, g)
    for i, p in enumerate(parts[:-1], 1):
        s2.append(nxt(s2, p, migrate={"part": i, "parts": len(parts)}))
    with pytest.raises(StoreRefused, match="not signed by the records key"):                                   # the store checks it at link k
        s2.append(nxt(s2, parts[-1], migrate={"part": len(parts), "parts": len(parts)}))
    s.close()
    s2.close()


# --- the verifier path ------------------------------------------------------------------------------------------------

def test_a_replay_proves_the_migration_again_or_says_it_cannot(url):
    s, _, _ = migrated(url)
    again = RP.replay(s.links(), PUB, "example", RP.side_of(s))
    assert again.migration() == "proven" and RP.records(again) == RP.records(s)
    sha = RP.genesis(s)["change"]["yaml"]["sha256"]
    s.side_delete("genesis_yaml", sha)                       # erased: the names in the YAML bytes go
    erased = RP.replay(s.links(), PUB, "example", RP.side_of(s))
    assert erased.migration() == RP.ERASED == "not re-provable: the YAML bytes were erased"
    assert erased.root() == s.root() and RP.records(erased) == RP.records(s)    # the chain verifies as before
    s.close()


# --- what never enters a link -----------------------------------------------------------------------------------------

def test_visits_and_proof_tokens_go_to_the_side_table_counted(url):
    doc = fixture()
    doc["approval_proofs"] = [{"records": ["M-example-0001"], "by": "idp:7c1f-ann", "token": TOKEN}]
    doc["visits"] = [{"visit_id": "V-in-records", "host": "idp:7c1f-ann"}]            # a store from before 0.16
    files = [{"visit": {"visit_id": "V-file"}, "visit_events": [{"event_id": "VE-1", "visit_id": "V-file"}],
              "badges": [{"badge_id": "B-1", "visit_id": "V-file"}]}]
    s, raw, got = migrated(url, doc, visits=files)
    assert (got["visits"], got["visit_events"], got["badges"], got["proof_tokens"]) == (2, 1, 1, 1)
    assert got["migration"] == "proven"
    for sealed in s.links():
        body = base64.b64decode(sealed["bytes"])
        assert TOKEN.encode() not in body and b"V-in-records" not in body and b"V-file" not in body
    rec = RP.records(s)
    assert rec["approval_proofs"] == as_logged(s, doc)["approval_proofs"]
    assert {v["visit_id"] for v in rec["visits"]} == {"V-in-records", "V-file"}
    s.close()


# --- a desk store, stopped --------------------------------------------------------------------------------------------

def _desk(tmp_path):
    key = tmp_path / "records.key"
    key.write_text(KEY.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    return DeskStore(tmp_path / "desk", key, FIXTURE), key


def test_a_desk_store_migrates_only_while_no_desk_holds_it(tmp_path):
    desk, key = _desk(tmp_path)
    out = tmp_path / "log.db"
    with pytest.raises(StoreRefused, match="a desk process holds .*Stop the desk"):
        M.migrate_desk_store(tmp_path / "desk", out, dev_key=key)
    assert not out.exists()
    rev = desk.revision()
    desk.close()
    got = M.migrate_desk_store(tmp_path / "desk", out, dev_key=key)
    assert got["migration"] == "proven" and got["revision"] == rev
    with pytest.raises(StoreRefused, match="exists: a migration writes a new store file"):
        M.migrate_desk_store(tmp_path / "desk", out, dev_key=key)


def test_a_failed_migration_leaves_no_store_file(tmp_path, monkeypatch):
    desk, key = _desk(tmp_path)
    desk.close()
    real = M.split
    monkeypatch.setattr(M, "split", lambda doc, visits=None: (lambda h, o, s: (h, o[1:], s))(*real(doc, visits)))
    out = tmp_path / "log.db"
    with pytest.raises(StoreRefused, match="differ from the signed YAML"):
        M.migrate_desk_store(tmp_path / "desk", out, dev_key=key)
    assert not any(p.name.startswith("log.db") for p in tmp_path.iterdir())


def test_the_command_line_says_why_and_what_to_do(tmp_path, capsys):
    desk, key = _desk(tmp_path)
    cfg = ROOT / "tests" / "fixtures" / "config.yaml"
    assert M.main([str(tmp_path / "desk"), str(tmp_path / "log.db"), "--dev-key", str(key), "--config", str(cfg), "--preview"]) == 1
    assert "Stop the desk" in capsys.readouterr().err
    desk.close()
    assert M.main([str(tmp_path / "desk"), str(tmp_path / "log.db"), "--dev-key", str(key), "--config", str(cfg), "--preview"]) == 0
    assert "migration proven" in capsys.readouterr().err
    assert M.main(["--export", str(tmp_path / "log.db"), "--pinned", PUB, "--realm", "example", "--config", str(cfg)]) == 0
    s = open_store(f"sqlite:{tmp_path / 'log.db'}", PUB, "example")
    assert M.meaning(R.loads(capsys.readouterr().out)) == M.meaning(as_logged(s, fixture()))
    s.close()


# --- decision 0028: the internal anchor ------------------------------------------------------------------------------

def _original_anchors(doc):
    from keyclerk import anchors as A
    return {v for kind in R.ANCHOR_PATHS for rec in ([doc[kind]] if isinstance(doc.get(kind), dict) else doc.get(kind) or [])
            if isinstance(rec, dict) for _, v in R.anchor_values(kind, rec) if A.is_person(v)}


def test_no_link_holds_an_identity_providers_id(url):
    doc = fixture()
    s, raw, got = migrated(url, doc)
    originals = _original_anchors(doc)
    assert originals and got["anchors"] == len(originals)
    for sealed in s.links():
        body = base64.b64decode(sealed["bytes"])
        leaked = [a for a in originals if a.encode() in body]
        assert not leaked, f"a link holds identity-provider ids: {leaked[:3]} in {body[:300]!r}"
    s.close()


def test_every_mapping_row_is_vouched_for_by_an_accounts_record(url):
    from keyclerk import anchors as A
    s, _, _ = migrated(url)
    rows = {r["anchor"]: r for _, r in s.side_scan("anchor_map")}
    doc = RP.records(s)
    accounts = {a["anchor"]: a["commit"] for a in doc["accounts"]}
    assert rows and set(rows) == set(accounts)                         # persons or not: owners, approvers, contacts
    for anchor, row in rows.items():
        assert A.row_matches(row, [accounts[anchor]])
        assert s.side_get("anchor_idp", A.idp_key(row["idp"]))["anchor"] == anchor
    assert all("commits" not in p for p in doc["persons"]) and all(A.is_internal(a) for p in doc["persons"]
                                                                    for a in p["anchors"])
    s.close()


def test_an_erased_mapping_row_ends_only_the_re_provability(url):
    s, _, _ = migrated(url)
    key, _ = next(iter(s.side_scan("anchor_map")))
    s.side_delete("anchor_map", key)
    assert RP.prove_migration(s, PUB) == RP.ERASED_MAP
    RP.replay(s.links(), PUB, s.realm, RP.side_of(s))           # the chain itself still verifies
    s.close()


def test_visit_files_are_re_keyed_too(url):
    from keyclerk import anchors as A
    files = [{"visit": {"visit_id": "V-file", "host": "idp:7c1f-ann"},
              "visit_events": [{"event_id": "VE-1", "visit_id": "V-file", "by": "idp:91d0-bert"}], "badges": []}]
    s, _, _ = migrated(url, visits=files)
    v = s.side_get("visits", "V-file")
    e = s.side_get("visit_events", "VE-1")
    assert A.is_internal(v["host"]) and A.is_internal(e["by"])
    s.close()


def test_the_command_migrates_without_preview_from_0_26_0(tmp_path):
    desk, key = _desk(tmp_path)
    desk.close()
    cfg = ROOT / "tests" / "fixtures" / "config.yaml"
    assert M.main([str(tmp_path / "desk"), str(tmp_path / "log.db"), "--dev-key", str(key), "--config", str(cfg)]) == 0
    assert (tmp_path / "log.db").exists()
