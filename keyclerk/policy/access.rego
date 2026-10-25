# Grant decisions at the local PDP. The data is data.keyclerk.grants as built by
# keyclerk.grants.opa_data: grants keyed by the person's anchor (never the broker's local sub) and the revoked
# grant ids (a revoked grant never returns). A role or group claim in a token is never consulted: the PEP
# passes the anchor, the role, the scope and the context, and the decision comes from the bundle.
package keyclerk.access

import rego.v1

now := time.parse_rfc3339_ns(input.context.time)

revoked contains id if some id in data.keyclerk.grants.revoked

holds(class) := g if {
	some g in data.keyclerk.grants.by_anchor[input.subject.anchor]
	g.class == class
	g.role == input.resource.role
	g.scope == input.resource.scope
	not revoked[g.grant_id]
	time.parse_rfc3339_ns(g.start) <= now
	now < time.parse_rfc3339_ns(g.end)
}

# Bands that may activate (rules_as_data band floor): green or amber; red only reduces, black ends everything.
activating_bands := {"green", "amber"}

# The request is checked before anything is decided: identifiers in the narrow set, a zoned RFC 3339 time, a known
# band, a bounded bundle age. A malformed request decides nothing (every rule below requires input_ok).
valid_id(x) if {
	is_string(x)
	regex.match(`^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,255}$`, x)
}

input_ok if {
	valid_id(input.subject.anchor)
	valid_id(input.resource.role)
	is_object(input.resource.scope)
	is_string(input.context.time)
	regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(Z|[+-][0-9]{2}:[0-9]{2})$`, input.context.time)
	input.context.band in {"green", "amber", "red", "black"}
	is_number(input.context.bundle_age_hours)
	input.context.bundle_age_hours >= 0
}

default activate := false

# An activation is allowed when an activation grant is active, an eligibility covers it, the persona is the admin
# persona, the band allows it and, while cut off, the bundle is still inside its freshness.
activate if {
	input_ok
	g := holds("activation")
	g.persona == "admin"
	input.subject.persona == "admin" # the persona from the token, never inferred from the anchor
	holds("eligibility")
	input.context.band in activating_bands
	proof_enough(g)
	fresh
}

default use := false

# A functional duty is usable while its grant is active and the band is not black.
use if {
	input_ok
	holds("functional")
	input.context.band != "black"
	fresh
}

# Bundle freshness (policy_feed.bundle_integrity): past the horizon nothing widens.
default fresh := false

fresh if input.context.bundle_age_hours <= data.keyclerk.grants_rules.horizon_hours

reasons contains "revoked" if {
	some g in data.keyclerk.grants.by_anchor[input.subject.anchor]
	g.role == input.resource.role
	revoked[g.grant_id]
}

reasons contains "band" if not input.context.band in activating_bands

reasons contains "stale-bundle" if not fresh

# Proof trust and session trust are two inputs: the band above is the session; proof trust
# per claim must reach the floor of the grant's label (Internal low, Sensitive medium, Restricted high), from rule data.
trust_rank := {"none": 0, "low": 1, "medium": 2, "high": 3}

proof_enough(g) if {
	floor := data.keyclerk.grants_rules.proof_floor[g.label_ceiling]
	trust_rank[object.get(input.context, ["proof_trust", "identity"], "none")] >= trust_rank[floor]
}

reasons contains "proof-trust" if {
	some g in data.keyclerk.grants.by_anchor[input.subject.anchor]
	g.role == input.resource.role
	not proof_enough(g)
}
