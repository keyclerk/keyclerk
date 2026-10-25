package keyclerk.identity_test

import rego.v1

import data.keyclerk.identity

on := {"privileged_needs_admin": true, "machines_in_privileged": false, "persona_rule": "warn"}

enforce := object.union(on, {"persona_rule": "enforce"})

test_change_1_enforce_needs_an_admin_purpose if {
	r := identity.membership with input as {"member": {"kind": "tenant", "purpose": "unspecified"}, "group": {"risk": "privileged"}, "settings": enforce}
	count(r) == 1
	identity.membership with input as {"member": {"kind": "tenant", "purpose": "unspecified"}, "group": {"risk": "privileged"}, "settings": on} == []
	identity.membership with input as {"member": {"kind": "tenant", "purpose": "admin"}, "group": {"risk": "privileged"}, "settings": enforce} == []
}

test_change_1_actor if {
	identity.actor with input as {"actor": {"purpose": "admin", "exact": true}, "group": {"risk": "privileged"}, "settings": enforce} == []
	daily := identity.actor with input as {"actor": {"purpose": "daily", "exact": true}, "group": {"risk": "privileged"}, "settings": enforce}
	count(daily) == 1
	other := identity.actor with input as {"actor": {"purpose": "admin", "exact": false}, "group": {"risk": "low"}, "settings": enforce}
	count(other) == 1
	identity.actor with input as {"actor": {"purpose": "daily", "exact": false}, "group": {"risk": "privileged"}, "settings": on} == []
}

ask(member, risk) := r if {
	r := identity.membership with input as {"member": member, "group": {"risk": risk}, "settings": on}
}

test_a_daily_account_stays_out_of_privileged_groups if {
	ask({"kind": "tenant", "purpose": "daily"}, "privileged") == ["a privileged group takes an admin persona, not a daily account"]
	ask({"kind": "tenant", "purpose": "admin"}, "privileged") == []
	ask({"kind": "tenant", "purpose": "daily"}, "elevated") == []
	ask({"kind": "tenant", "purpose": "unspecified"}, "privileged") == []
}

test_workloads_and_agents if {
	ask({"kind": "workload"}, "low") == []
	ask({"kind": "workload"}, "privileged") != []
	ask({"kind": "agent", "director_kind": "workload"}, "low") == []
	ask({"kind": "agent", "director_kind": "tenant"}, "elevated") == []
	ask({"kind": "agent", "director_kind": "agent"}, "low") != []
	ask({"kind": "agent"}, "low") != []
}

test_externals_still_come_through_leases if {
	ask({"kind": "external"}, "low") == ["externals come through leases only"]
}

test_an_agent_reaches_only_as_far_as_its_director if {
	identity.reach with input as {"kind": "agent", "director_member": true, "director_suspended": false}
	not identity.reach with input as {"kind": "agent", "director_member": false, "director_suspended": false}
	not identity.reach with input as {"kind": "agent", "director_member": true, "director_suspended": true}
	identity.reach with input as {"kind": "tenant"}
}
