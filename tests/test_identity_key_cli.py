# SPDX-License-Identifier: EUPL-1.2
"""The 0.29.0 upgrade's commands (0021): the signer pins the reconciler's key, derived from its --mark-key, and takes
over a desk's bundle key once so enrolled edges keep their pin."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import edge as E
from keyclerk import init, signer


def _key_file(path, key):
    path.write_text(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    return path


def test_the_identity_key_is_the_public_half_of_the_reconcilers_mark_key(tmp_path, capsys):
    mark = Ed25519PrivateKey.generate()
    out = tmp_path / "identity.pub"
    assert init.main(["identity-key", "--mark-key", str(_key_file(tmp_path / "mark", mark)), "--out", str(out)]) == 0
    assert signer.read_identity_key(out) == E.public_hex(mark)
    assert "--identity-key" in capsys.readouterr().out


def test_a_file_that_is_not_a_public_key_is_refused(tmp_path):
    bad = tmp_path / "bad.pub"
    bad.write_text("not a key\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="Ed25519 public key"):
        signer.read_identity_key(bad)
    with pytest.raises(SystemExit, match="private key"):
        init.main(["identity-key", "--mark-key", str(bad), "--out", str(tmp_path / "x")])


def test_a_desks_bundle_key_is_imported_once_and_another_is_refused(tmp_path, capsys):
    desk_key = tmp_path / "bundle.key"
    E.load_or_make_key(desk_key, allow_create=True)
    state = tmp_path / "signer"
    assert signer.main(["import-bundle-key", "--state", str(state), "--from", str(desk_key)]) == 0
    assert "delete" in capsys.readouterr().out
    assert (state / "edge" / "bundle.key").read_bytes() == desk_key.read_bytes()
    assert signer.main(["import-bundle-key", "--state", str(state), "--from", str(desk_key)]) == 0   # the same: fine
    other = tmp_path / "other.key"
    E.load_or_make_key(other, allow_create=True)
    with pytest.raises(SystemExit, match="another bundle key"):
        signer.main(["import-bundle-key", "--state", str(state), "--from", str(other)])
