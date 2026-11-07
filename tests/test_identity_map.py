# SPDX-License-Identifier: EUPL-1.2
"""The sealed identity map (0021 point 2): the reconciler seals each person's broker username and verified e-mail, so
the checking signer can refuse a lease that names another account or address."""
import json
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E, identity_map as M
from keyclerk import reconcile as Rc

from test_reconcile import AT, MarkedBroker, args, doc, mark_key_file, write

KEY = Ed25519PrivateKey.generate()
PUB = E.public_hex(KEY)


def sealed(at=AT, realm="r", **kw):
    return M.seal(KEY, realm, kw.get("revision", 3), at, kw.get("usernames", {"a1": "ann"}),
                  kw.get("emails", {"a1": ("ann" + "@example.org"), "a2": ("bo" + "@example.org")}))


def test_a_map_opens_under_the_pinned_key_for_its_realm():
    m = M.open_map(sealed(), PUB, "r")
    assert M.usernames(m) == {"a1": "ann"} and M.emails(m) == {"a1": ("ann" + "@example.org"), "a2": ("bo" + "@example.org")}
    assert m["people"]["a2"] == {"username": None, "email": ("bo" + "@example.org")} and m["revision"] == 3


def test_a_map_by_another_key_or_for_another_realm_is_refused():
    with pytest.raises(ValueError, match="pinned"):
        M.open_map(sealed(), E.public_hex(Ed25519PrivateKey.generate()), "r")
    with pytest.raises(ValueError, match="realm"):
        M.open_map(sealed(realm="other"), PUB, "r")


def test_an_older_map_is_a_replay():
    newer = M.open_map(sealed(), PUB, "r")
    with pytest.raises(ValueError, match="replay"):
        M.open_map(sealed(at=AT - timedelta(minutes=1)), PUB, "r", not_before=newer["at"])
    assert M.open_map(sealed(at=AT), PUB, "r", not_before=newer["at"])       # the same map again is no replay


def test_an_entry_is_exactly_a_username_and_an_email():
    bad = E.seal(KEY, {"realm": "r", "revision": 1, "at": E._iso(AT),
                       "people": {"a1": {"username": "ann", "email": None, "role": "admin"}}}, M.FORMAT)
    with pytest.raises(ValueError, match="exactly"):
        M.open_map(bad, PUB, "r")


def test_the_reconciler_seals_the_map_with_its_mark_key(tmp_path):
    b, key = MarkedBroker(), mark_key_file(tmp_path)
    b.usernames, b.emails = {"a1": "ann"}, {"a1": ("ann" + "@example.org")}
    d = doc()
    d["revision"] = 3
    assert Rc.run_once(args(tmp_path, write(tmp_path, d, "r3.yaml"), mark_key=key), AT, b)["applied"]
    pub = E.public_hex(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path(key).read_text(encoding="utf-8"))))
    got = json.loads((tmp_path / "state" / "identity-map.json").read_text(encoding="utf-8"))
    m = M.open_map(got, pub, args(tmp_path, None).realm)
    assert M.usernames(m) == {"a1": "ann"} and M.emails(m) == {"a1": ("ann" + "@example.org")} and m["revision"] == 3
    assert m["at"] == E._iso(AT) and M.at_of(m) == AT
