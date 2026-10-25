# What a viewer may see of one person's graph (decision 0009, D7 and D8). The engine evaluates it compiled to
# WebAssembly (keyclerk.policy_wasm); code gathers the facts, this file decides. Need to know: a viewer and the root
# see everything; a person sees themselves; a manager sees a person who is in a group they manage, holds a
# delegation in their chain, or has a role at a place they look after, and of that person only what lies in the
# manager's own tree, chain and places. Accounts (which identity provider, which other accounts) are for the viewer,
# the root and the person themselves.
#
# input.viewer:  {all, self, tree: [group], delegations: [id], places: [place]}
# input.subject: {groups: [group], delegations: [id], places: [place]}
# input.nodes:   [{id, kind, contexts: [{group | delegation | place: id}]}]
package keyclerk.view

import rego.v1

v := input.viewer

s := input.subject

default whole := false

whole if v.all

whole if v.self

subject_visible if whole

subject_visible if {
	some g in s.groups
	g in v.tree
}

subject_visible if {
	some d in s.delegations
	d in v.delegations
}

subject_visible if {
	some p in s.places
	p in v.places
}

in_view(c) if c.group in v.tree

in_view(c) if c.delegation in v.delegations

in_view(c) if c.place in v.places

node_visible(n) if whole

node_visible(n) if {
	not whole
	n.kind == "subject"
}

node_visible(n) if {
	not whole
	n.kind != "subject"
	n.kind != "account"
	some c in n.contexts
	in_view(c)
}

decision := {
	"subject": true,
	"nodes": [n.id | some n in input.nodes; node_visible(n)],
	"realm": object.get(v, "all", false) == true,
	"accounts": whole,
} if subject_visible

else := {"subject": false, "nodes": [], "realm": false, "accounts": false}
