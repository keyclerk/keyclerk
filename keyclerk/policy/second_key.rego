# Who counts as a second key (decision 0008). The one definition of the rule: the engine evaluates it compiled to
# WebAssembly (keyclerk.policy_wasm) with facts it gathers per approver, and delegation.rego calls counts/1 with the
# same facts built from data.keyclerk.admin_authority. Facts are gathered by code; this file decides.
#
# A candidate (one approver of one record) has the facts:
#   anchor, kind ("tenant" | "external" | "agent"), actor, member, root (booleans: is that person),
#   in_chain (inside the actor's delegation chain, above or below), tainted (compromised at the time),
#   officer (the security officer), named (a named approver appointed for the time), manager (holds a power over
#   the group or a group above it, through a chain other than the actor's), unit_differs (true | false | null when a
#   unit is unknown), reciprocal_days_ago (days since the actor's key was on a change this approver made, the favour this
#   approval would return, or null when never), persona_ok (false when the persona rule is enforced, the group is
#   privileged and the approving account is not an admin persona; absent means true, decision 0011a).
# The policy: {"standing": "off" | "warn" | "enforce", "reciprocity_days": number}.
package keyclerk.second_key

import rego.v1

pol := object.get(input, "policy", {})

# Independent of the actor: today's rule (outside the chain, a person of the organisation).
independent(c) if {
	c.kind == "tenant"
	object.get(c, "persona_ok", true) == true
	not c.actor
	not c.member
	not c.root
	not c.in_chain
	not c.tainted
}

# Standing for the purpose: by role, by appointment, or by managing the group through another chain.
standing(c) if c.officer

standing(c) if c.named

standing(c) if {
	c.manager
	c.unit_differs != false # a sibling deputy from another unit, where units are recorded
}

reciprocal(c, p) if {
	is_number(c.reciprocal_days_ago)
	c.reciprocal_days_ago < object.get(p, "reciprocity_days", 30)
}

# The rule with standing (decision 0008): what counts once standing is enforced.
counts(c, p) if {
	independent(c)
	standing(c)
	not reciprocal(c, p)
}

has_standing(c) if standing(c)

else := false

is_reciprocal(c, p) if reciprocal(c, p)

else := false

checks(c, p) := [
	[c.kind != "tenant", "not a person of the organisation"],
	[object.get(c, "persona_ok", true) == false, "approved from an account that is not an admin persona (a privileged group)"],
	[c.actor == true, "the actor"],
	[c.member == true, "the member"],
	[c.root == true, "the root is never a second key"],
	[c.in_chain == true, "inside the actor's chain of delegations"],
	[c.tainted == true, "compromised at the time"],
	[has_standing(c) == false, "no standing: not the security officer, a named approver, or a manager of the group through another chain"],
	[is_reciprocal(c, p), "returns a favour: the actor approved a change of theirs within the reciprocity window"],
]

reasons(c, p) := [pair[1] | some pair in checks(c, p); pair[0] == true]

counting(cands, p) := [c.anchor | some c in cands; counts(c, p)] if p.standing == "enforce"

else := [c.anchor | some c in cands; independent(c)]

# The rule as a function, for policies that build candidates from their own data (delegation.rego).
evaluate(cands, p) := {
	"independent": [c.anchor | some c in cands; independent(c)],
	"with_standing": [c.anchor | some c in cands; counts(c, p)],
	"counting": counting(cands, p),
	"why_not": {c.anchor: reasons(c, p) | some c in cands; not counts(c, p)},
}

# Entry point of the compiled policy: candidates and policy come in the input.
decision := evaluate(input.candidates, pol)
