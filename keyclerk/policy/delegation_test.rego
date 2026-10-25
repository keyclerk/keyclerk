# Unit tests for keyclerk.delegation.
package keyclerk.delegation_test

import rego.v1

import data.keyclerk.delegation

adm := {
	"authority": {
		"owner": [{"delegation_id": "root", "powers": ["delegate", "includes", "members", "rules", "subgroups"], "groups": ["office", "finance", "admins"], "max_risk": "privileged", "chain_people": ["owner"]}],
		"ann": [{"delegation_id": "D-1", "powers": ["delegate", "includes", "members", "rules"], "groups": ["office", "finance"], "max_risk": "elevated", "chain_people": ["owner", "ann", "bert"]}],
	},
	"risk": {"office": "low", "finance": "elevated", "admins": "privileged"},
	"deputies": ["ann", "bert"],
	"persons": {"ann": "p-ann", "ann-2": "p-ann", "owner": "p-owner", "bert": "p-bert"},
	"widenings_today": {"p-ann": 3},
	"revision": 4,
	"rules": {"widenings_per_deputy_per_day": 20},
}

req(action, group, member) := {"actor": "ann", "action": action, "group": group, "member": member, "assertion_fresh": true, "min_revision": 4}

test_a_deputy_adds_within_their_subtree if {
	delegation.allow with input as req("add_member", "office", "gina") with data.keyclerk.admin_authority as adm
}

test_outside_the_subtree_is_refused if {
	not delegation.allow with input as req("add_member", "admins", "gina") with data.keyclerk.admin_authority as adm
}

test_self_by_another_anchor_is_refused if {
	r := delegation.deny_reasons with input as req("add_member", "office", "ann-2") with data.keyclerk.admin_authority as adm
	"You cannot add yourself." in r
}

test_a_deputy_into_an_elevated_group_needs_an_outside_key if {
	not delegation.allow with input as req("add_member", "finance", "bert") with data.keyclerk.admin_authority as adm
	not delegation.allow with input as object.union(req("add_member", "finance", "bert"), {"approvers": ["owner"]}) with data.keyclerk.admin_authority as adm
	delegation.allow with input as object.union(req("add_member", "finance", "bert"), {"approvers": ["ingrid"]}) with data.keyclerk.admin_authority as adm
}

test_a_stale_bundle_is_refused if {
	not delegation.allow with input as object.union(req("add_member", "office", "gina"), {"min_revision": 5}) with data.keyclerk.admin_authority as adm
}

test_never_on_behalf_or_by_an_agent if {
	not delegation.allow with input as object.union(req("add_member", "office", "gina"), {"actor_chain": ["assistant", "ann"]}) with data.keyclerk.admin_authority as adm
	not delegation.allow with input as object.union(req("add_member", "office", "gina"), {"actor_kind": "agent"}) with data.keyclerk.admin_authority as adm
}

test_a_widening_needs_a_fresh_assertion if {
	not delegation.allow with input as object.union(req("add_member", "office", "gina"), {"assertion_fresh": false}) with data.keyclerk.admin_authority as adm
}

test_rules_never_on_privileged_groups if {
	r := delegation.deny_reasons with input as object.union(req("add_rule", "admins", ""), {"actor": "owner", "approvers": ["ingrid"]}) with data.keyclerk.admin_authority as adm
	"A privileged group has named members only: no rules and no included groups." in r
}

test_cut_off_only_ends if {
	cut := {"context": {"connectivity": "cut_off"}}
	not delegation.allow with input as object.union(req("add_member", "office", "gina"), cut) with data.keyclerk.admin_authority as adm
	delegation.allow with input as object.union(object.union(req("end_member", "office", "gina"), cut), {"assertion_fresh": false}) with data.keyclerk.admin_authority as adm
}

test_the_daily_limit_holds if {
	busy := object.union(adm, {"widenings_today": {"p-ann": 20}})
	not delegation.allow with input as req("add_member", "office", "gina") with data.keyclerk.admin_authority as busy
}

test_malformed_requests_are_refused if {
	r := delegation.deny_reasons with input as object.union(req("add_member", "office", "gina"), {"actor": "ann\" or 1"}) with data.keyclerk.admin_authority as adm
	"Malformed request." in r
	not delegation.allow with input as object.union(req("add_member", "office", "gina"), {"approvers": ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]}) with data.keyclerk.admin_authority as adm
}
