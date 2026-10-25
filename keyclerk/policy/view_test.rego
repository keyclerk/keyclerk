package keyclerk.view_test

import rego.v1

import data.keyclerk.view

nodes := [
	{"id": "p", "kind": "subject", "contexts": []},
	{"id": "a1", "kind": "account", "contexts": []},
	{"id": "g:finance", "kind": "group", "contexts": [{"group": "finance"}]},
	{"id": "g:admins", "kind": "group", "contexts": [{"group": "admins"}]},
	{"id": "x:bob", "kind": "person", "contexts": [{"delegation": "D-2"}]},
	{"id": "pl:heverlee", "kind": "place", "contexts": [{"place": "place:heverlee"}]},
]

subject := {"groups": ["finance", "admins"], "delegations": [], "places": []}

viewer(extra) := object.union({"all": false, "self": false, "tree": [], "delegations": [], "places": []}, extra)

test_a_viewer_sees_everything_and_the_realm if {
	d := view.decision with input as {"viewer": viewer({"all": true}), "subject": subject, "nodes": nodes}
	count(d.nodes) == count(nodes)
	d.realm
	d.accounts
}

test_a_person_sees_themselves_but_not_the_realm if {
	d := view.decision with input as {"viewer": viewer({"self": true}), "subject": subject, "nodes": nodes}
	count(d.nodes) == count(nodes)
	not d.realm
}

test_a_manager_sees_only_their_part_and_no_accounts if {
	d := view.decision with input as {"viewer": viewer({"tree": ["finance", "office"]}), "subject": subject, "nodes": nodes}
	d.subject
	{x | some x in d.nodes} == {"p", "g:finance"}
	not d.accounts
}

test_a_stranger_sees_nothing if {
	d := view.decision with input as {"viewer": viewer({"tree": ["sites"]}), "subject": subject, "nodes": nodes}
	not d.subject
	d.nodes == []
}

test_a_place_steward_sees_the_place_and_people_through_their_chain if {
	sub := {"groups": [], "delegations": ["D-2"], "places": ["place:heverlee"]}
	d := view.decision with input as {"viewer": viewer({"places": ["place:heverlee"], "delegations": ["D-2"]}), "subject": sub, "nodes": nodes}
	{x | some x in d.nodes} == {"p", "x:bob", "pl:heverlee"}
}
