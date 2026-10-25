# SPDX-License-Identifier: EUPL-1.2
"""keyclerk init: the first run writes the minimal records, the engine's checks accept them, and a desk seeded from them
lets the root act (a fresh install otherwise has nothing anyone can act on)."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import init, records
from keyclerk.desk import Desk, Store
from keyclerk.reconcile import check_records
from keyclerk.signer import Signer

CONFIG = Path(__file__).resolve().parent / "fixtures" / "config.yaml"
ROOT, OFFICER, EDGE = "idp:root-1", "idp:officer-1", "idp:edge-1"


def run(target: Path, **over) -> int:
    flags = {"realm": "example", "root": ROOT, "officer": OFFICER, "entitlement": "admin-console",
             "application": "keyclerk", "risk": "privileged", "group": "all", **over}
    argv = [str(target), "--config", str(CONFIG), "--no-input"]
    for k, v in flags.items():
        if v is not None:
            argv += ["--" + k.replace("_", "-"), v]
    return init.main(argv)


def _key(path: Path) -> Ed25519PrivateKey:
    k = Ed25519PrivateKey.generate()
    path.write_text(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    return k


def test_a_scripted_init_writes_records_the_engine_accepts_in_both_forms(tmp_path, capsys):
    target = tmp_path / "records"
    assert run(target, edge_officer=EDGE) == 0
    written = sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file())
    assert written == ["catalogue/admin-console.yaml", "groups/all.yaml", "realm.yaml", "seed.yaml"]
    as_dir = records.load(target)
    as_file = records.loads((target / "seed.yaml").read_text(encoding="utf-8"))
    assert check_records(as_dir) == [] and check_records(as_file) == []
    assert as_file["root"]["officer"] == OFFICER and as_file["root"]["holders"][0]["anchor"] == ROOT
    assert {a for p in as_file["persons"] for a in p["anchors"]} == {ROOT, OFFICER, EDGE}
    assert as_file["groups"] == [{"group_id": "all", "parent": None, "max_risk": "privileged",
                                  "carries": [{"entitlement": "admin-console", "by": ROOT}]}]
    out = capsys.readouterr().out
    assert "seed.yaml" in out and "--seed" in out and "source of joiners" in out


def test_the_root_and_the_security_officer_are_two_people(tmp_path, capsys):
    assert run(tmp_path / "records", officer=ROOT) == 1
    err = capsys.readouterr().err
    assert "one anchor" in err and "next:" in err
    assert not (tmp_path / "records").exists()


@pytest.mark.parametrize("edge", [ROOT, OFFICER])
def test_an_edge_officer_from_the_core_is_refused(tmp_path, capsys, edge):
    assert run(tmp_path / "records", edge_officer=edge) == 1
    assert "never a core administrator" in capsys.readouterr().err
    assert not (tmp_path / "records").exists()


def test_a_target_that_is_not_empty_is_never_overwritten(tmp_path, capsys):
    target = tmp_path / "records"
    target.mkdir()
    (target / "realm.yaml").write_text("realm: other\n", encoding="utf-8")
    assert run(target) == 1
    assert "not an empty directory" in capsys.readouterr().err
    assert (target / "realm.yaml").read_text(encoding="utf-8") == "realm: other\n"
    assert run(tmp_path / "fresh") == 0 and run(tmp_path / "fresh") == 1      # a second run on its own output too


def test_an_empty_existing_target_is_used(tmp_path):
    (tmp_path / "records").mkdir()
    assert run(tmp_path / "records") == 0
    assert (tmp_path / "records" / "realm.yaml").is_file()


def test_a_missing_value_without_a_terminal_names_its_flag(tmp_path, capsys):
    assert run(tmp_path / "records", group=None) == 1
    assert "--group is missing" in capsys.readouterr().err


def test_a_bad_value_names_the_flag_and_what_it_takes(tmp_path, capsys):
    assert run(tmp_path / "records", risk="extreme") == 1
    assert "--risk is one of low, elevated, privileged" in capsys.readouterr().err
    assert run(tmp_path / "records", group="Top Group") == 1
    assert "--group" in capsys.readouterr().err


def test_the_engines_checks_refuse_and_nothing_is_written(tmp_path, capsys):
    assert run(tmp_path / "records", risk="privileged", group_risk="low") == 1   # carries more than its fixed class
    assert "the engine's checks refuse" in capsys.readouterr().err
    assert not (tmp_path / "records").exists()
    assert not [p for p in tmp_path.iterdir()]                                # no half-written work directory left


def test_an_owner_who_is_not_the_root_becomes_a_first_administrator(tmp_path):
    assert run(tmp_path / "records", owner="idp:owner-1") == 0
    doc = records.load(tmp_path / "records")
    assert {"person": "entitlement-owner", "kind": "tenant", "anchors": ["idp:owner-1"],   # privileged: an admin persona
            "personas": [{"anchor": "idp:owner-1", "purpose": "admin"}]} in doc["persons"]
    assert doc["groups"][0]["carries"] == [{"entitlement": "admin-console", "by": "idp:owner-1"}]


def test_after_init_the_root_creates_a_subgroup_at_the_desk(tmp_path):
    assert run(tmp_path / "records") == 0
    _key(tmp_path / "key")
    desk = Desk(Store(tmp_path / "store", tmp_path / "key", tmp_path / "records" / "seed.yaml"))
    assert desk.store.revision() == 1
    r = desk.propose({"anchor": ROOT, "roles": []}, {"action": "create_group", "parent": "all", "group_id": "office"})
    assert r["outcome"] == "applied" and r["revision"] == 2
    assert {g["group_id"] for g in desk.store.load()["groups"]} == {"all", "office"}


def test_the_checking_signer_signs_the_first_revision_and_checks_the_next(tmp_path):
    assert run(tmp_path / "records") == 0
    signer = Signer(_key(tmp_path / "key"), tmp_path / "signer")
    desk = Desk(Store(tmp_path / "store", None, tmp_path / "records" / "seed.yaml", signer=signer))
    raw = (tmp_path / "store" / "records.yaml").read_bytes()
    sig = bytes.fromhex((tmp_path / "store" / "records.yaml.sig").read_text(encoding="ascii").strip())
    signer.key.public_key().verify(sig, raw)                                  # revision 1, signed by the signer's key
    r = desk.propose({"anchor": ROOT, "roles": []}, {"action": "create_group", "parent": "all", "group_id": "office"})
    assert r["outcome"] == "applied" and r["revision"] == 2


def test_init_asks_for_each_missing_value_and_asks_again_after_a_bad_answer(tmp_path, capsys):
    a = init.parser().parse_args([str(tmp_path / "records")])
    answers = iter(["example", "", ROOT, ROOT, OFFICER, "admin-console", "keyclerk", "extreme", "low", "", "all", "", ""])
    asked = []
    v = init.collect(a, lambda p: (asked.append(p), next(answers))[1])
    assert v["root"] == ROOT and v["officer"] == OFFICER and v["risk"] == "low" and v["home"] is None
    err = capsys.readouterr().err
    assert "one anchor" in err and "--risk is one of" in err                   # each bad answer, then the question again
    with pytest.raises(init.InitRefused, match="one anchor"):
        init.build({**v, "officer": ROOT})
    doc = init.build(v)
    assert check_records(doc) == [] and doc["home"] == "example"


def test_on_a_privileged_top_group_the_first_administrators_hold_admin_personas(tmp_path, monkeypatch):
    """With the persona rule enforced (the default), power over a privileged group and membership in it take an admin
    persona (decision 0011a). Init writes one on each first administrator's anchor, so the root can add the security
    officer to the top group: the change then waits only for its second key, never for a missing persona."""
    from keyclerk import delegation as D
    real = D.identity_rules
    monkeypatch.setattr(D, "identity_rules", lambda: {**real(), "persona_rule": "enforce"})
    assert run(tmp_path / "records") == 0
    doc = records.load(tmp_path / "records")
    assert all(p.get("personas") == [{"anchor": p["anchors"][0], "purpose": "admin"}] for p in doc["persons"])
    _key(tmp_path / "key")
    desk = Desk(Store(tmp_path / "store", tmp_path / "key", tmp_path / "records" / "seed.yaml"))
    r = desk.propose({"anchor": ROOT, "roles": []}, {"action": "add_member", "group": "all", "anchor": OFFICER, "days": 1})
    assert not any("admin persona" in x for x in r["reasons"]), r["reasons"]
    assert r["outcome"] == "pending" and any("second key" in x for x in r["reasons"]), r


def test_below_privileged_init_writes_no_personas(tmp_path):
    assert run(tmp_path / "records", risk="elevated") == 0
    assert not any("personas" in p for p in records.load(tmp_path / "records")["persons"])
