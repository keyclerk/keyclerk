package keyclerk.tree_test

import rego.v1

import data.keyclerk.tree

# root > D-1 (ann) > D-3 (cas); root > D-2 (bert) > D-4 (dirk) > D-5 (eva)
nodes := [
	{"id": "root", "chain": ["root"]},
	{"id": "D-1", "chain": ["D-1", "root"]},
	{"id": "D-2", "chain": ["D-2", "root"]},
	{"id": "D-3", "chain": ["D-3", "D-1", "root"]},
	{"id": "D-4", "chain": ["D-4", "D-2", "root"]},
	{"id": "D-5", "chain": ["D-5", "D-4", "D-2", "root"]},
]

test_a_viewer_sees_the_whole_tree if {
	d := tree.decision with input as {"viewer": {"all": true, "held": []}, "nodes": nodes}
	count(d.nodes) == count(nodes)
	d.whole
}

test_a_deputy_sees_below_and_above_but_not_siblings if {
	d := tree.decision with input as {"viewer": {"all": false, "held": ["D-4"]}, "nodes": nodes}
	{x | some x in d.nodes} == {"root", "D-2", "D-4", "D-5"}
	not d.whole
}

test_a_first_level_deputy_does_not_see_the_other_branch if {
	d := tree.decision with input as {"viewer": {"all": false, "held": ["D-1"]}, "nodes": nodes}
	{x | some x in d.nodes} == {"root", "D-1", "D-3"}
}

test_someone_without_a_delegation_sees_nothing if {
	d := tree.decision with input as {"viewer": {"all": false, "held": []}, "nodes": nodes}
	d.nodes == []
}

test_holding_an_unknown_id_reveals_nothing if {
	d := tree.decision with input as {"viewer": {"all": false, "held": ["D-9"]}, "nodes": nodes}
	d.nodes == []
}
