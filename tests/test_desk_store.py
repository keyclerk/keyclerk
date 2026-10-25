# SPDX-License-Identifier: EUPL-1.2
"""The desk's store protocol (decision 0022, S5 step T1): the desk calls nothing on its store that the protocol does
not name, the signed YAML store provides all of it, and the configuration chooses the store."""
import ast
from pathlib import Path

import jsonschema
import pytest

from keyclerk import config, desk
from keyclerk.store import desk_store as DS

ROOT = Path(__file__).resolve().parents[1]
MEMBERS = {n for n in DS.DeskStore.__annotations__} | {
    n for n, v in vars(DS.DeskStore).items() if callable(v) and not n.startswith("_")}


def _desk_store_calls() -> set[str]:
    """Every attribute the Desk class reads on self.store."""
    tree = ast.parse((ROOT / "keyclerk" / "desk.py").read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Desk")
    return {n.attr for n in ast.walk(cls)
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Attribute) and n.value.attr == "store"
            and isinstance(n.value.value, ast.Name) and n.value.value.id == "self"}


def test_the_desk_calls_only_what_the_protocol_names():
    assert _desk_store_calls() <= MEMBERS, sorted(_desk_store_calls() - MEMBERS)


def test_the_yaml_store_provides_the_whole_protocol():
    missing = [m for m in MEMBERS if not hasattr(desk.YamlStore, m) and m != "path"]
    assert not missing and desk.Store is desk.YamlStore


def test_a_yaml_store_is_a_desk_store(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    s = desk.YamlStore(tmp_path / "store", key, ROOT / "tests" / "fixtures" / "records.yaml")
    try:
        assert isinstance(s, DS.DeskStore)
        before = len(s.log(1000))
        line = s.note({"change_id": "C-a0b1c2", "action": "probe", "outcome": "refused", "summary": "a probe"})
        assert line["action"] == "probe" and len(s.log(1000)) == before + 1 and not s.verify_log()
    finally:
        s.close()


def test_the_configuration_chooses_the_store():
    assert DS.kind(None) == "yaml" and DS.kind({}) == "yaml" and DS.kind({"store": {}}) == "yaml"
    assert DS.kind({"store": {"kind": "sqlite"}}) == "sqlite"
    with pytest.raises(ValueError, match="one of yaml, sqlite"):
        DS.kind({"store": {"kind": "postgres"}})
    check = jsonschema.Draft202012Validator(config.schema("config")["properties"]["store"])
    assert check.is_valid({"kind": "sqlite"}) and check.is_valid({})
    assert not check.is_valid({"kind": "postgres"}) and not check.is_valid({"kind": "yaml", "path": "x"})


def test_sqlite_needs_the_checking_signer_and_says_how(tmp_path):
    with pytest.raises(DS.StoreChoiceRefused, match="--signer") as e:
        DS.open_desk_store({"store": {"kind": "sqlite"}}, tmp_path / "store", tmp_path / "records.key")
    assert "never holds the records key" in str(e.value) and not (tmp_path / "store").exists()
