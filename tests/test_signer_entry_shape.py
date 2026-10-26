# SPDX-License-Identifier: EUPL-1.2
"""A link keeps an entry's structure, never free text or provider ids (decision 0028): the signer checks the shape."""
import pytest
from tests.test_signer_replica import ADD, change_ops, world  # noqa: F401 - fixture
from tests.test_signer_t2 import _base

from keyclerk.signer import SignerRefused


def test_a_link_entry_carries_no_free_text_and_no_provider_id(world, tmp_path):
    s = world["signer"]
    ops = change_ops(tmp_path, ADD, world)
    entry = {"change_id": "C-a3a3a3", "action": "add_member", "actor": "idp:7c1f-ann",
             "summary": "Ann Example (ann.example" + "@" + "example.org) added Finn Newman"}   # built: no address here
    with pytest.raises(SignerRefused):
        s.propose(_base(s), {"ops": ops, "entry": entry}, [])
