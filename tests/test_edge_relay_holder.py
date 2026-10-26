# SPDX-License-Identifier: EUPL-1.2
"""A lease credential is relayed only to the holder of that lease."""
import shutil

import pytest

import tests.test_edge_api as _TA
from keyclerk import relay as R
from tests.test_edge_api import call, _bundle_with_ceiling, ANN, FINN


def test_relay_for_one_lease_goes_only_to_that_leases_holder(two_holder_server):
    base, desk = two_holder_server
    body = _bundle_with_ceiling(base)
    ann = next(x for x in body["leases"] if x["person"] == ANN)
    finn = next(x for x in body["leases"] if x["person"] != ANN and x["key_id"])   # another holder with a person key
    purpose = "lease:" + ann["lease_id"]
    env = R.encrypt(finn["public_key"], b"looks-like-anns-credential", purpose)
    code, _ = call(base, "POST", "/edge/relay", {"key_id": finn["key_id"], "envelope": env, "purpose": purpose})
    assert code == 422, "relay for Ann's lease accepted for another holder (Gina)"

GINA_ADMIN = ('  - {membership_id: M-example-0099, group: admins, member: {anchor: "idp:77dd-gina"}, by: "idp:2b9e-owner", '
              'under: root, approved_by: ["op:7a1e-oscar"], start: 2026-10-01T00:00:00Z, end: 2026-12-31T00:00:00Z}\n')


@pytest.fixture
def two_holder_server(tmp_path, monkeypatch):
    """edge_server, with Gina also in the admins group: two people hold leases on plant-a."""
    fx = tmp_path / "fixtures"
    shutil.copytree(_TA.FIXTURES, fx)
    lines = (fx / "records.yaml").read_text(encoding="utf-8").splitlines(keepends=True)
    i = next(n for n, line in enumerate(lines) if "M-example-0006" in line)
    lines.insert(i + 1, GINA_ADMIN)
    (fx / "records.yaml").write_text("".join(lines), encoding="utf-8")
    monkeypatch.setattr(_TA, "FIXTURES", fx)
    gen = _TA.edge_server.__wrapped__(tmp_path) if hasattr(_TA.edge_server, "__wrapped__") else None
    if gen is None:
        raise RuntimeError("cannot reuse edge_server")
    yield next(gen)
    try:
        next(gen)
    except StopIteration:
        pass
