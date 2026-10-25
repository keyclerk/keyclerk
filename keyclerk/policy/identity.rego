# Personas, workloads and agents (decision 0011). The engine evaluates it compiled to WebAssembly (keyclerk.policy_wasm);
# code gathers the facts, this file decides.
#
#   membership  may this account be a member of a group of this class (judged on every effective member, 0011a)
#   reach       does an agent's membership count now: only while its director is a member too (on behalf of)
#   actor       may this account use a power (the root, a delegation) over a group of this class (0011a)
#
# settings.persona_rule rolls the stricter rules out as decision 0008 did: off, warn (the default: nothing changes, an
# impact list shows what enforce would do) or enforce.
package keyclerk.identity

import rego.v1

# --- membership --------------------------------------------------------------------------------------------------
# input: {member: {kind, purpose, director_kind}, group: {risk}, settings: {privileged_needs_admin,
#         machines_in_privileged}}

m := input.member

refusal contains "externals come through leases only" if m.kind == "external"

refusal contains "the account is not a person, workload or agent in the records" if m.kind == "unknown"

refusal contains "an agent needs a director (a person or a workload) it acts for" if {
	m.kind == "agent"
	not object.get(m, "director_kind", "") in {"tenant", "workload"}
}

refusal contains "a workload or an agent is never a member of a privileged group" if {
	m.kind in {"workload", "agent"}
	input.group.risk == "privileged"
	not input.settings.machines_in_privileged
}

# the daily account of a person reads mail and the web: a privileged group takes only their admin persona
refusal contains "a privileged group takes an admin persona, not a daily account" if {
	m.kind == "tenant"
	m.purpose == "daily"
	input.group.risk == "privileged"
	input.settings.privileged_needs_admin
}

enforcing if input.settings.persona_rule == "enforce"

# an account with no stated purpose, or any purpose but admin, holds no privileged right (0011a, change 1)
refusal contains "a privileged group takes an admin persona; this account states no admin purpose" if {
	enforcing
	m.kind == "tenant"
	m.purpose != "admin"
	m.purpose != "daily"
	input.group.risk == "privileged"
}

membership := sort(refusal)

# --- actor -------------------------------------------------------------------------------------------------------
# input: {actor: {purpose, exact}, group: {risk}, settings}; exact: the acting account is the one the role names

actor_refusal contains "power over a privileged group is used from an admin persona, not a daily account" if {
	enforcing
	input.group.risk == "privileged"
	input.actor.purpose != "admin"
}

actor_refusal contains "the role belongs to another account of this person: act from the account it names" if {
	enforcing
	not input.actor.exact
}

actor := sort(actor_refusal)

# --- reach -------------------------------------------------------------------------------------------------------
# input: {kind, director_member, director_suspended}

default reach := true

reach := false if {
	input.kind == "agent"
	not input.director_member
}

reach := false if {
	input.kind == "agent"
	input.director_suspended
}
