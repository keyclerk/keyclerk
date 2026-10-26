# SPDX-License-Identifier: EUPL-1.2
"""A new account's mapping row carries no broker subject: only the reconciler links one, later (decision 0028)."""
import uuid

import pytest
from tests.test_signer_replica import world  # noqa: F401 - fixture
from tests.test_signer_t2 import _base, _new_person

from keyclerk import anchors as A
from keyclerk.signer import SignerRefused
from keyclerk.store import replay as RP
from keyclerk.store.log_reconcile import Identities


def test_a_new_accounts_row_cannot_arrive_pre_linked_to_a_subject_the_desk_chose(world):
    s = world["signer"]
    other_sub = str(uuid.uuid4())
    row = {**A.mapping_row("idp:a1b2-newcomer"), "sub": other_sub}
    try:
        s.propose(_base(s), {"ops": _new_person(s, row), "entry": {"change_id": "C-a2a2a2"}}, [], [row])
    except SignerRefused:
        return                                                   # fixed: a row enters without a subject
    ids = Identities(RP.records(s.replica), s.replica)
    assert ids.out(row["anchor"]) != f"uid:{other_sub}", \
        "the new hire's access would be written to the broker account the desk chose"
