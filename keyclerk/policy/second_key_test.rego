package keyclerk.second_key_test

import rego.v1

import data.keyclerk.second_key

base := {
	"anchor": "a", "kind": "tenant", "actor": false, "member": false, "root": false, "in_chain": false,
	"tainted": false, "officer": false, "named": false, "manager": false, "unit_differs": null,
	"reciprocal_days_ago": null,
}

inp(c, standing) := {"candidates": [c], "policy": {"standing": standing, "reciprocity_days": 30}}

with_(extra) := object.union(base, extra)

test_a_plain_member_counts_only_until_standing_is_enforced if {
	second_key.decision.counting == ["a"] with input as inp(base, "warn")
	second_key.decision.counting == [] with input as inp(base, "enforce")
	why := second_key.decision.why_not.a with input as inp(base, "enforce")
	"no standing: not the security officer, a named approver, or a manager of the group through another chain" in why
}

test_the_officer_and_a_named_approver_have_standing if {
	second_key.decision.counting == ["a"] with input as inp(with_({"officer": true}), "enforce")
	second_key.decision.counting == ["a"] with input as inp(with_({"named": true}), "enforce")
}

test_a_sibling_manager_counts_unless_known_to_share_the_unit if {
	second_key.decision.counting == ["a"] with input as inp(with_({"manager": true}), "enforce")
	second_key.decision.counting == ["a"] with input as inp(with_({"manager": true, "unit_differs": true}), "enforce")
	second_key.decision.counting == [] with input as inp(with_({"manager": true, "unit_differs": false}), "enforce")
	second_key.decision.counting == ["a"] with input as inp(with_({"officer": true, "unit_differs": false}), "enforce")
}

test_reciprocity_inside_the_window_never_counts if {
	second_key.decision.counting == [] with input as inp(with_({"named": true, "reciprocal_days_ago": 3}), "enforce")
	second_key.decision.counting == ["a"] with input as inp(with_({"named": true, "reciprocal_days_ago": 31}), "enforce")
	zero := {"candidates": [with_({"named": true, "reciprocal_days_ago": 3})], "policy": {"standing": "enforce", "reciprocity_days": 0}}
	second_key.decision.counting == ["a"] with input as zero
}

test_the_root_an_external_the_chain_the_actor_and_the_tainted_never_count if {
	every c in [
		with_({"root": true, "officer": true}),
		with_({"kind": "external", "named": true}),
		with_({"in_chain": true, "officer": true}),
		with_({"actor": true, "named": true}),
		with_({"tainted": true, "officer": true}),
	] {
		second_key.decision.counting == [] with input as inp(c, "enforce")
		second_key.decision.counting == [] with input as inp(c, "warn")
	}
}
