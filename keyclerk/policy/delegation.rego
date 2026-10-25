# Administrative acts on the group tree. The data is data.keyclerk.admin_authority as built by
# keyclerk.delegation.opa_data: who holds which powers over which groups now (the chain to root is checked there), each
# group's effective risk class, the persons behind anchors and the administrative revision. The portal and the engine
# ask allow; deny_reasons tells the actor why in plain words.
package keyclerk.delegation

import rego.v1

import data.keyclerk.second_key

adm := data.keyclerk.admin_authority

power := {
	"add_member": "members", "renew_member": "members", "end_member": "members",
	"include": "includes", "add_rule": "rules", "create_subgroup": "subgroups", "delegate": "delegate",
}

widening := {"add_member", "renew_member", "include", "add_rule", "create_subgroup", "delegate"}

person(anchor) := adm.persons[anchor] if anchor in object.keys(adm.persons)

else := anchor

risk_rank := {"low": 0, "elevated": 1, "privileged": 2}

group_risk := adm.risk[input.group] if input.group in object.keys(adm.risk)

else := "privileged"

# The delegations under which the actor holds the needed power over the group, within its risk class.
holding contains a if {
	some a in adm.authority[input.actor]
	power[input.action] in a.powers
	input.group in a.groups
	risk_rank[group_risk] <= risk_rank[a.max_risk]
}

# A second key (decision 0008): the facts per approver come from the policy data, the rule from second_key.rego.
sk := object.get(adm, "second_key", {})

in_chain(k) if {
	some a in holding
	person(k) in {person(x) | some x in a.chain_people}
}

managed_by(k) if {
	some a in object.get(adm.authority, k, [])
	a.delegation_id != "root"
	input.group in a.groups
}

unit_differs(k) := null if {
	not object.get(sk, "units", {})[k]
} else := null if {
	not object.get(sk, "units", {})[input.actor]
} else := sk.units[k] != sk.units[input.actor]

candidate(k) := {
	"anchor": k,
	"kind": object.get(object.get(sk, "kinds", {}), k, object.get(sk, "default_kind", "tenant")),
	"actor": person(k) == person(input.actor),
	"member": person(k) == person(object.get(input, "member", "")),
	"root": person(k) == person(object.get(sk, "root", "")),
	"in_chain": in_chain(k),
	"tainted": k in object.get(sk, "tainted", []),
	"officer": person(k) == person(object.get(sk, "officer", "")),
	"named": person(k) in {person(x) | some x in object.get(sk, "named", [])},
	"manager": managed_by(k),
	"unit_differs": unit_differs(k),
	"reciprocal_days_ago": object.get(object.get(object.get(sk, "favours", {}), person(k), {}), person(input.actor), null),
}

default in_chain(_) := false

default managed_by(_) := false

second_key_result := second_key.evaluate(
	[candidate(k) | some k in object.get(input, "approvers", [])],
	object.get(sk, "policy", {"standing": "warn", "reciprocity_days": 30}),
)

second_keys contains k if some k in second_key_result.counting

needs_second_key if group_risk == "privileged"

needs_second_key if {
	input.action == "add_rule"
	group_risk == "elevated"
}

needs_second_key if {
	input.action in {"add_member", "renew_member"}
	risk_rank[group_risk] >= 1
	input.member in adm.deputies
}

deny_reasons contains "The policy data is older than the newest revocation you know of; try again in a moment." if {
	adm.revision < object.get(input, "min_revision", 0)
}

deny_reasons contains "Group administration is never done on someone's behalf or by an agent." if {
	count(object.get(input, "actor_chain", [input.actor])) > 1
}

deny_reasons contains "Group administration is never done on someone's behalf or by an agent." if {
	object.get(input, "actor_kind", "tenant") != "tenant"
}

deny_reasons contains "You hold no delegation that covers this group for this action." if {
	input.action in object.keys(power)
	count(holding) == 0
}

deny_reasons contains "Unknown action." if not input.action in object.keys(power)

valid_id(x) if {
	is_string(x)
	regex.match(`^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,255}$`, x)
}

deny_reasons contains "Malformed request." if not valid_id(input.actor)

deny_reasons contains "Malformed request." if not valid_id(input.group)

deny_reasons contains "Malformed request." if {
	input.member
	not valid_id(input.member)
}

deny_reasons contains "Malformed request." if {
	some k in object.get(input, "approvers", [])
	not valid_id(k)
}

deny_reasons contains "Malformed request." if count(object.get(input, "approvers", [])) > 10

deny_reasons contains "Confirm with your passkey first: every widening carries a fresh signed assertion." if {
	input.action in widening
	not input.assertion_fresh
}

deny_reasons contains "You cannot add yourself." if {
	input.action in {"add_member", "renew_member"}
	person(input.member) == person(input.actor)
}

deny_reasons contains "This group needs a second key from someone outside your delegation chain." if {
	input.action in widening
	needs_second_key
	count(second_keys) == 0
}

deny_reasons contains "A privileged group has named members only: no rules and no included groups." if {
	input.action in {"add_rule", "include"}
	group_risk == "privileged"
}

deny_reasons contains "Today's limit of widenings for you is reached; your delegator can continue." if {
	input.action in widening
	object.get(adm.widenings_today, person(input.actor), 0) >= adm.rules.widenings_per_deputy_per_day
}

deny_reasons contains "The site is cut off: only ending memberships is possible until it reconnects." if {
	input.action in widening
	object.get(object.get(input, "context", {}), "connectivity", "connected") == "cut_off"
}

default allow := false

allow if count(deny_reasons) == 0
