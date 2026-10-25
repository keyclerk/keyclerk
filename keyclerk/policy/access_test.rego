# Unit tests for keyclerk.access: activation needs an active activation grant, a covering eligibility,
# the admin persona, a green or amber band and a fresh bundle; a revoked grant never counts; claims are never read.
package keyclerk.access_test

import rego.v1

import data.keyclerk.access

scope := {"level": "tenant", "id": "t1"}

g(id, class, start, end) := {"grant_id": id, "role": "tenant-admin-privileged", "class": class, "scope": scope, "start": start, "end": end, "persona": "admin", "label_ceiling": "Sensitive", "plane": "tenant"}

data_ok := {"by_anchor": {"a1": [
	g("G-t1-0001", "eligibility", "2026-10-01T00:00:00Z", "2026-12-31T00:00:00Z"),
	g("G-t1-0002", "activation", "2026-10-21T08:00:00Z", "2026-10-21T12:00:00Z"),
]}, "revoked": []}

rules := {"horizon_hours": 168, "proof_floor": {"Internal": "low", "Sensitive": "medium", "Restricted": "high"}}

req(t, band, age) := {
	"subject": {"anchor": "a1", "persona": "admin"},
	"resource": {"role": "tenant-admin-privileged", "scope": scope},
	"context": {"time": t, "band": band, "bundle_age_hours": age, "proof_trust": {"identity": "medium"}},
}

test_activation_inside_its_window_is_allowed if {
	access.activate with input as req("2026-10-21T09:00:00Z", "green", 1) with data.keyclerk.grants as data_ok with data.keyclerk.grants_rules as rules
}

test_activation_after_its_end_is_refused if {
	not access.activate with input as req("2026-10-21T12:00:00Z", "green", 1) with data.keyclerk.grants as data_ok with data.keyclerk.grants_rules as rules
}

test_red_band_refuses_activation if {
	not access.activate with input as req("2026-10-21T09:00:00Z", "red", 1) with data.keyclerk.grants as data_ok with data.keyclerk.grants_rules as rules
}

test_stale_bundle_refuses_activation if {
	not access.activate with input as req("2026-10-21T09:00:00Z", "green", 169) with data.keyclerk.grants as data_ok with data.keyclerk.grants_rules as rules
}

test_revoked_eligibility_ends_activation if {
	d := object.union(data_ok, {"revoked": ["G-t1-0001"]})
	not access.activate with input as req("2026-10-21T09:00:00Z", "green", 1) with data.keyclerk.grants as d with data.keyclerk.grants_rules as rules
	"revoked" in access.reasons with input as req("2026-10-21T09:00:00Z", "green", 1) with data.keyclerk.grants as d with data.keyclerk.grants_rules as rules
}

test_activation_without_eligibility_is_refused if {
	d := {"by_anchor": {"a1": [g("G-t1-0002", "activation", "2026-10-21T08:00:00Z", "2026-10-21T12:00:00Z")]}, "revoked": []}
	not access.activate with input as req("2026-10-21T09:00:00Z", "green", 1) with data.keyclerk.grants as d with data.keyclerk.grants_rules as rules
}

test_a_role_claim_in_the_token_grants_nothing if {
	r := object.union(req("2026-10-21T09:00:00Z", "green", 1), {"subject": {"anchor": "nobody", "claims": {"roles": ["tenant-admin-privileged"]}}})
	not access.activate with input as r with data.keyclerk.grants as data_ok with data.keyclerk.grants_rules as rules
}

test_a_base_person_session_cannot_activate if {
	r := object.union(req("2026-10-21T09:00:00Z", "green", 1), {"subject": {"anchor": "a1", "persona": "person"}})
	not access.activate with input as r with data.keyclerk.grants as data_ok with data.keyclerk.grants_rules as rules
}

test_low_proof_trust_refuses_a_sensitive_activation if {
	r := json.patch(req("2026-10-21T09:00:00Z", "green", 1), [{"op": "replace", "path": "/context/proof_trust/identity", "value": "low"}])
	not access.activate with input as r with data.keyclerk.grants as data_ok with data.keyclerk.grants_rules as rules
	"proof-trust" in access.reasons with input as r with data.keyclerk.grants as data_ok with data.keyclerk.grants_rules as rules
}

test_a_green_session_never_stands_in_for_missing_proof if {
	r := json.remove(req("2026-10-21T09:00:00Z", "green", 1), ["/context/proof_trust"])
	not access.activate with input as r with data.keyclerk.grants as data_ok with data.keyclerk.grants_rules as rules
}

# discovery, authorisation first: a grant pre-assigned to the corporate IdP's immutable id (Entra oid) works on
# the person's very first request; nothing about the broker's own user is needed.
test_a_pre_assigned_grant_is_honoured_on_the_first_token if {
	pre := {"by_anchor": {"entra-oid:7f3c9a10-55e2-4d8b-9c11-2a6b0f4e8d21": [{
		"grant_id": "G-t-0099", "role": "tenant-admin", "class": "functional", "scope": scope,
		"start": "2026-10-20T00:00:00Z", "end": "2026-11-20T00:00:00Z", "persona": "person", "label_ceiling": "Internal", "plane": "tenant",
	}]}, "revoked": []}
	first := {
		"subject": {"anchor": "entra-oid:7f3c9a10-55e2-4d8b-9c11-2a6b0f4e8d21", "persona": "person"},
		"resource": {"role": "tenant-admin", "scope": scope},
		"context": {"time": "2026-10-21T09:00:00Z", "band": "green", "bundle_age_hours": 1, "proof_trust": {"identity": "low"}},
	}
	access.use with input as first with data.keyclerk.grants as pre with data.keyclerk.grants_rules as rules
}

test_a_malformed_request_decides_nothing if {
	not access.activate with input as object.union(req("2026-10-21T10:00:00Z", "green", 1), {"context": {"time": "2026-10-21T10:00:00", "band": "green", "bundle_age_hours": 1}}) with data.keyclerk.grants as data_ok with data.keyclerk.grants_rules as rules
}
