# SPDX-License-Identifier: EUPL-1.2
"""Provider ids and broker subjects never share a key in the reverse table: an id never starts with sub:."""
import uuid

from tests.test_signer_replica import world  # noqa: F401 - fixture
from tests.test_signer_t2 import _base, _new_person

from keyclerk import anchors as A
from keyclerk.signer import SignerRefused


def test_an_identity_provider_id_cannot_occupy_a_subjects_key(world):
    s = world["signer"]
    holder_sub = str(uuid.uuid4())
    row = A.mapping_row("sub:" + holder_sub)
    try:
        s.propose(_base(s), {"ops": _new_person(s, row), "entry": {"change_id": "C-a4a4a4"}}, [], [row])
    except SignerRefused:
        return                                                   # fixed
    assert A.resolve(s.replica, {"sub": holder_sub, "anchor": "idp:anything"}) != row["anchor"], \
        "the holder's own sign-in resolves to an anchor the desk minted"
