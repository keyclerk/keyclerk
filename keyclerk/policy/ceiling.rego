# What an edge's ceiling allows (decision 0014 point 4). The officer signs the ceiling as data; this policy, shipped and
# signed with KeyClerk, reads it, in the core when a bundle is cut and in the edge agent from the same module. Core
# policy narrows; the ceiling is never widened by it.
#
# input: {"ceiling": {persons, roles, targets, classes, max_lease_hours, max_offline_hours, profile, ...},
#         "entry": {"kind": "lease" | "visit", "person", "roles": [...], "targets": [...], "class", "hours",
#                   "attested_profile": "assured" | "basic" | null}}
package keyclerk.ceiling

import rego.v1

person_inside if input.entry.person in input.ceiling.persons

# a role (a group of the core) admits only to low-class leases: core administrators control group membership, so for
# elevated and privileged leases and for visits the officer names the persons
person_inside if {
	input.entry.kind == "lease"
	input.entry.class == "low"
	some r in object.get(input.entry, "roles", [])
	r in input.ceiling.roles
}

refusals contains "the person is outside the edge's ceiling" if not person_inside

refusals contains "a target outside the edge's ceiling" if {
	some t in input.entry.targets
	not t in input.ceiling.targets
}

refusals contains "a lease class the ceiling does not allow" if {
	input.entry.kind == "lease"
	not input.entry.class in input.ceiling.classes
}

refusals contains "longer than the ceiling's longest lease" if {
	input.entry.kind == "lease"
	input.entry.hours > input.ceiling.max_lease_hours
}

refusals contains "a visit window longer than the ceiling's longest offline validity" if {
	input.entry.kind == "visit"
	input.entry.hours > input.ceiling.max_offline_hours
}

refusals contains "visit leases need an assured edge, by its ceiling and its attestation" if {
	input.entry.kind == "visit"
	input.ceiling.profile != "assured"
}

refusals contains "visit leases need an assured edge, by its ceiling and its attestation" if {
	input.entry.kind == "visit"
	object.get(input.entry, "attested_profile", null) != "assured"
}

decision := {"allow": count(refusals) == 0, "refusals": refusals}
