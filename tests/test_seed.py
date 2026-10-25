"""The first revision is judged like any change: a seed that fails the engine's checks is signed by nobody, whether the
checking signer or the desk's own key would sign it, and a migration's genesis is judged as well as proven."""
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import records
from keyclerk.desk import Store, StoreFault
from keyclerk.signer import Signer, SignerRefused

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "records.yaml"


def bad_seed(tmp_path) -> Path:
    doc = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    doc["memberships"][0]["group"] = "no-such-group"          # the engine refuses it: unknown group
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return p


def test_a_seed_the_engine_refuses_is_not_signed_by_the_checking_signer(tmp_path):
    signer = Signer(Ed25519PrivateKey.generate(), tmp_path / "signer")
    with pytest.raises(SignerRefused, match="the first revision is refused, nothing was signed.*unknown group"):
        Store(tmp_path / "desk", None, bad_seed(tmp_path), signer=signer)
    assert not (tmp_path / "signer" / "last.json").exists()
    assert not (tmp_path / "desk" / "records.yaml").exists()


def test_a_valid_seed_is_signed_as_revision_1_and_judged_like_any_change(tmp_path):
    signer = Signer(Ed25519PrivateKey.generate(), tmp_path / "signer")
    store = Store(tmp_path / "desk", None, FIXTURE, signer=signer)
    assert store.revision() == 1 and signer._last()[0] == 1
    store.close()


def test_a_seed_the_engine_refuses_is_not_signed_by_the_desks_own_key(tmp_path):
    key = tmp_path / "records.key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    with pytest.raises(StoreFault, match="the seed records are refused, nothing was signed.*unknown group"):
        Store(tmp_path / "desk", key, bad_seed(tmp_path))
    assert not (tmp_path / "desk" / "records.yaml").exists()


def test_a_migration_genesis_is_judged_too(tmp_path):
    key = Ed25519PrivateKey.generate()
    raw = bad_seed(tmp_path).read_text(encoding="utf-8")
    raw = yaml.safe_dump({**yaml.safe_load(raw), "revision": 4}, sort_keys=False)
    signer = Signer(key, tmp_path / "signer")
    signer.adopt(raw, key.sign(raw.encode("utf-8")).hex())            # signed by this key, but the engine refuses it
    with pytest.raises(SignerRefused, match="does not pass the engine's checks, nothing was signed") as e:
        signer.migrate()
    assert "unknown group no-such-group" in str(e.value) and "\n    fix: " in str(e.value)   # each error, its fix
    assert signer.replica is None and not (tmp_path / "signer" / "replica.db").exists()


def test_a_records_directory_without_a_home_loads_without_one(tmp_path):
    doc = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    doc.pop("home", None)
    records.split(doc, tmp_path / "dir")
    loaded = records.load(tmp_path / "dir")
    assert "home" not in loaded
