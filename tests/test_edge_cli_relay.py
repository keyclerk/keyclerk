# SPDX-License-Identifier: EUPL-1.2
"""Decision 0027 on the officer's side: edge_cli writes the relay certificate and the site statement, and cosign signs
each under its own format, so the edge's verifier (keyclerk.edge_relay) accepts them and nothing else does."""
import json

import pytest

from keyclerk import edge as E
from keyclerk import edge_cli
from keyclerk import edge_relay as ER


def _run(capsys, *args) -> dict:
    assert edge_cli.main(list(args)) in (0, None)
    return json.loads(capsys.readouterr().out)


def _keys(tmp_path, *names):
    out = {}
    for n in names:
        path = tmp_path / f"{n}.key"
        k = E.load_or_make_key(path, allow_create=True)
        out[n] = (str(path), E.public_hex(k))
    return out


def test_an_officer_certifies_a_relay_key_the_edge_accepts(tmp_path, capsys):
    k = _keys(tmp_path, "officer", "relay")
    doc = _run(capsys, "relay-cert", "--officer-key", k["officer"][1], "--relay-key", k["relay"][1],
               "--edges", "edge-a", "--operations", "revoke_lease", "end_lease", "--serial", "1", "--days", "7")
    (tmp_path / "cert.json").write_text(json.dumps(doc), encoding="utf-8")
    sealed = _run(capsys, "cosign", str(tmp_path / "cert.json"), "--key", k["officer"][0])
    cert = ER._cert(sealed, k["officer"][1])
    assert cert["relay_key"] == k["relay"][1] and cert["edges"] == ["edge-a"]
    with pytest.raises(ValueError):                       # not an officer statement: its own label
        E.unseal_multi(sealed, [k["officer"][1]], E.OFFICER_FORMAT)


def test_a_relay_certificate_lives_at_most_31_days(tmp_path, capsys):
    k = _keys(tmp_path, "officer", "relay")
    assert edge_cli.main(["relay-cert", "--officer-key", k["officer"][1], "--relay-key", k["relay"][1], "--edges",
                          "edge-a", "--operations", "revoke_lease", "--serial", "1", "--days", "32"]) == 2


def test_the_site_key_and_a_node_sign_a_provisional_replacement(tmp_path, capsys):
    k = _keys(tmp_path, "site", "node")
    doc = _run(capsys, "site-statement", "--purpose", "provisional", "--edge", "edge-a", "--site-key", k["site"][1],
               "--node-key", k["node"][1], "--reason", "the first node's disk failed")
    (tmp_path / "st.json").write_text(json.dumps(doc), encoding="utf-8")
    once = _run(capsys, "cosign", str(tmp_path / "st.json"), "--key", k["site"][0])
    (tmp_path / "st1.json").write_text(json.dumps(once), encoding="utf-8")
    both = _run(capsys, "cosign", str(tmp_path / "st1.json"), "--key", k["node"][0])
    st = ER.verify_site(both, k["site"][1], "edge-a", "provisional")
    assert st["node_key"] == k["node"][1]
    with pytest.raises(ValueError):                       # signed for a replacement, never a promotion
        ER.verify_site(both, k["site"][1], "edge-a", "promotion")
