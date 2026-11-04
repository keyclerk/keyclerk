# SPDX-License-Identifier: EUPL-1.2
"""Review row E5, reproduced on Keycloak 26.8.1 in the lab (2026-11-04): a member of a child group under a managed
group is under the managed group in every token, yet the reconciler read only the managed group's own members. The
reconciler now reads child groups too and removes their members (operator, 2026-11-04); the child group stays."""
import uuid

from test_connectors import scim  # noqa: F401

from keyclerk.connectors.keycloak import KeycloakTarget

GRANT = "/grants/tenant-admin@tenant:t"


def _realm(data, url):
    ann, mal, eve = data.add_user("idp:ann"), data.add_user("idp:mal"), data.add_user("idp:eve")
    kc = KeycloakTarget(keycloak=url, realm="t", base=url + "/scim/v2", admin_token="x")
    kc.base = url
    kc.apply(kc.plan({(GRANT, "idp:ann")}, kc.read_full()), "k1", dry_run=False)
    made = next(g for g in data.groups.values() if g["displayName"] == "grants:tenant-admin@tenant:t")
    sub, deeper = str(uuid.uuid4()), str(uuid.uuid4())            # made by hand in the console, under ours
    data.groups[sub] = {"id": sub, "displayName": "sub", "members": [{"value": mal}]}
    data.groups[deeper] = {"id": deeper, "displayName": "deeper", "members": [{"value": eve}]}
    data.children = {made["id"]: [sub], sub: [deeper]}
    return kc, made, data.groups[sub], data.groups[deeper], (ann, mal, eve)


def test_members_of_child_groups_are_seen(scim):  # noqa: F811
    data, url = scim
    kc, *_ = _realm(data, url)
    have = kc.read_full()
    assert (GRANT + "/sub", "idp:mal") in have, have                              # FAILS on 0.26.x: unseen
    assert (GRANT + "/sub/deeper", "idp:eve") in have
    assert any(f["group"] == GRANT + "/sub" and "child group" in f["why"] for f in kc.findings)


def test_they_are_removed_and_logged_out_and_the_child_group_stays(scim):  # noqa: F811
    data, url = scim
    kc, made, sub, deeper, (ann, mal, eve) = _realm(data, url)
    done = kc.apply(kc.plan({(GRANT, "idp:ann")}, kc.read_full()), "k2", dry_run=False)
    assert sub["members"] == [] and deeper["members"] == []
    assert made["members"] == [{"value": ann}]                                      # the required member stays
    assert sub["id"] in data.groups and deeper["id"] in data.groups                 # never deleted
    assert {mal, eve} <= set(data.logouts), done
    assert kc.read_full() == {(GRANT, "idp:ann")}


def test_a_child_group_never_receives_a_member(scim):  # noqa: F811
    data, url = scim
    kc, _, sub, _, (ann, mal, _) = _realm(data, url)
    kc.read_full()
    done = kc.apply({"add": [(GRANT + "/sub", "idp:ann")], "remove": []}, "k3", dry_run=False)
    assert done["failed"] and not done["added"], done
    assert sub["members"] == [{"value": mal}]                                       # ann never added
