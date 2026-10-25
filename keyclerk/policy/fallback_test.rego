# Malformed fallback requests decide nothing but never.
package keyclerk.fallback_test

import rego.v1

import data.keyclerk.fallback

rd := {"allowed_steps": {"Sensitive": ["remote_confirm", "deferred"]}, "remote_steps_until_level": {"Sensitive": "high"},
	"steps": {"remote_confirm": {"obligations": []}, "deferred": {"obligations": []}, "never": {"obligations": []}}}

ok := {"ladder": ["remote_confirm", "deferred"], "label": "Sensitive", "band": "green", "level": "normal", "urgent": false,
	"available": {"site_office": true}}

test_a_well_formed_request_gets_its_step if {
	fallback.step == "remote_confirm" with input as ok with data.keyclerk.availability as rd
}

test_an_unknown_step_or_label_is_never if {
	fallback.step == "never" with input as object.union(ok, {"ladder": ["walk_in"]}) with data.keyclerk.availability as rd
	fallback.step == "never" with input as object.union(ok, {"label": "TopSecret"}) with data.keyclerk.availability as rd
	fallback.step == "never" with input as object.union(ok, {"urgent": "yes"}) with data.keyclerk.availability as rd
}

test_missing_until_level_closes_remote_steps if {
	partial := {"allowed_steps": {"Sensitive": ["remote_confirm", "deferred"]}, "remote_steps_until_level": {},
		"steps": rd.steps}
	fallback.step == "deferred" with input as ok with data.keyclerk.availability as partial
}
