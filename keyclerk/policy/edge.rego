# What an edge decides, with policy signed in the core (decision 0014 point 6). The same module
# runs in KeyClerk and, compiled to WebAssembly, in the edge agent; tests/conformance/edge.json pins its answers.
# Times are Unix seconds; a deployment changes the settings by policy, not on the edge.
package keyclerk.edge

import rego.v1

# hours a bundle's leases of each class stay valid after it was issued (0013 D3: horizons per class)
default horizons := {"low": 168, "elevated": 24, "privileged": 1}

# the longest visit-lease window, below the ceiling's longest offline validity
default visit_max_hours := 72

# how long the dedicated local access port stays open after link-up
default local_window_hours := 4

# the longest session a lease of each class may hold before the agent ends it; a target may set
# a shorter cap of its own in the edge record
default session_max_hours := {"low": 8, "elevated": 4, "privileged": 1}

# a carried visit lease lives at most this long, inside its visit lease's window
default carried_max_hours := 24

# phoned unlock: the longest unlock, and how many an edge may receive per hour
default unlock_max_minutes := 60

default unlock_per_hour := 3

# the core raises edge_silent when an edge has not pulled a bundle for this long
default pull_max_hours := 24

# decision 0016: the PCRs an assured edge's quote must match against the baseline its officer signed (PCR 7, the
# Secure Boot state, by default; a deployment adds 0 to 6 or a kernel baseline here)
default attest_pcrs := ["7"]

# whether an EK without a manufacturer certificate may be assured on its officer's pin alone
default require_ek_certificate := false

settings := {"horizons": horizons, "visit_max_hours": visit_max_hours, "local_window_hours": local_window_hours,
	"session_max_hours": session_max_hours, "carried_max_hours": carried_max_hours,
	"unlock_max_minutes": unlock_max_minutes, "unlock_per_hour": unlock_per_hour, "pull_max_hours": pull_max_hours,
	"attest_pcrs": attest_pcrs, "require_ek_certificate": require_ek_certificate}

# attestation: is a verified quote's state the one the officer signed? input: {quote: {pcrs: {"7": hex}},
# baseline: {"7": hex}, ek_certified: bool}. The quote's signature, nonce and digest are checked before this runs.
attestation := {"assured": count(attestation_refusals) == 0, "refusals": attestation_refusals}

attestation_refusals contains concat("", ["PCR ", p, " is not the baseline the officer signed"]) if {
	some p in attest_pcrs
	object.get(object.get(input, "quote", {}), ["pcrs", p], "missing") != object.get(object.get(input, "baseline", {}), p, "none")
}

attestation_refusals contains "the endorsement key has no manufacturer certificate, and this deployment requires one" if {
	require_ek_certificate
	not input.ek_certified
}

# admit: may this person open a session to this target now?
# input: {"person", "target", "now", "issued", "leases": [...], "visit_leases": [...], "revoked": [...]}
lease_ok(l) if {
	l.person == input.person
	l.target == input.target
	l.from <= input.now
	input.now < l.until
	not l.lease_id in input.revoked
	input.now - input.issued <= object.get(horizons, l.class, 0) * 3600
}

visit_ok(v) if {
	v.person == input.person
	input.target in v.targets
	v.from <= input.now
	input.now < v.until
	not v.lease_id in input.revoked
}

admitted_by contains l.lease_id if {
	some l in input.leases
	lease_ok(l)
}

admitted_by contains v.lease_id if {
	some v in input.visit_leases
	visit_ok(v)
}

admit := {"allow": count(admitted_by) > 0, "leases": admitted_by}

# visit_window: may a visit lease of this length be granted on this ceiling?
# input: {"hours", "max_offline_hours"}
visit_window := {"allow": input.hours <= visit_max_hours, "max_hours": visit_max_hours} if input.hours <= input.max_offline_hours

visit_window := {"allow": false, "max_hours": input.max_offline_hours} if input.hours > input.max_offline_hours
