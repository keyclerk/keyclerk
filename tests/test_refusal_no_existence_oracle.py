# SPDX-License-Identifier: EUPL-1.2
"""A write about something that does not exist is refused in the same words, with the same next step, as one about
something that is not the writer's; only the root and the security officer, who see every record, get the plain
answer. Every preview leaves a line in the log (review 2026-10-26, C1)."""
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from tests.test_api import ANN, FIXTURES

from keyclerk.desk import Desk, Refusal, Store

OFFICER = {"sub": "s-ingrid", "name": "ingrid", "anchor": "idp:31ee-ingrid", "roles": [], "csrf": None}


@pytest.fixture
def desk(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    return Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"))


def _refusal(desk, who, body, ident):
    with pytest.raises(Refusal) as e:
        desk.preview(who, body)
    return str(e.value).replace(ident, "<id>"), json.dumps(e.value.next, sort_keys=True).replace(ident, "<id>")


@pytest.mark.parametrize("missing, theirs", [
    ({"action": "add_member", "group": "no-such-group", "anchor": "idp:44aa-dirk"},
     {"action": "add_member", "group": "admins", "anchor": "idp:44aa-dirk"}),
    ({"action": "end_membership", "membership_id": "M-example-9999", "reason": "left the team"},
     {"action": "end_membership", "membership_id": "M-example-0006", "reason": "left the team"}),
    ({"action": "end_delegation", "delegation_id": "D-example-9999", "reason": "no longer needed"},
     {"action": "end_delegation", "delegation_id": "D-example-0002", "reason": "no longer needed"}),
])
def test_missing_and_not_yours_answer_alike(desk, missing, theirs):
    key = next(k for k in ("group", "membership_id", "delegation_id") if k in missing)
    a = _refusal(desk, ANN, missing, missing[key])
    b = _refusal(desk, ANN, theirs, theirs[key])
    assert a == b
    assert json.loads(a[1]), "the refusal still says why and what completes the intent"


def test_ending_an_appointment_says_who_ends_one_before_whether_it_exists(desk):
    msg, _ = _refusal(desk, ANN, {"action": "end_approver", "approver_id": "A-example-9999", "reason": "rotation"},
                      "A-example-9999")
    assert msg == "only the root trust owner or the security officer ends an appointment"


def test_a_visit_that_does_not_exist_is_one_you_take_no_part_in(desk):
    msg, nxt = _refusal(desk, ANN, {"action": "add_attendee", "visit_id": "V-example-9999", "party": "p1"}, "V-example-9999")
    assert msg == "you take no part in that visit" and json.loads(nxt)[0]["who"] == []


def test_the_officer_who_sees_every_record_gets_the_plain_answer(desk):
    for body, text in (({"action": "end_membership", "membership_id": "M-example-9999", "reason": "left the team"},
                        "there is no membership M-example-9999"),
                       ({"action": "add_attendee", "visit_id": "V-example-9999", "party": "p1"}, "there is no such visit")):
        with pytest.raises(Refusal, match=text):
            desk.preview(OFFICER, body)


def test_every_preview_leaves_a_line_refused_or_not(desk):
    with pytest.raises(Refusal):
        desk.preview(ANN, {"action": "add_member", "group": "no-such-group", "anchor": "idp:44aa-dirk"})
    desk.preview(ANN, {"action": "add_member", "group": "finance", "anchor": "idp:44aa-dirk"})
    lines = [json.loads(x) for x in (desk.store.path / "log.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    previews = [(e["outcome"], e["answer"], e["records"]) for e in lines if e.get("outcome") == "preview"]
    assert previews == [("preview", "refused", {}), ("preview", "pending", {})]
