package keyclerk.edge_test

import rego.v1

import data.keyclerk.ceiling
import data.keyclerk.edge

lease := {"lease_id": "L-1", "person": "idp:7c1f-ann", "target": "plc-ssh", "class": "privileged", "from": 1000, "until": 100000}

visit := {"lease_id": "V-1", "person": "idp:7c1f-ann", "targets": ["plc-ssh"], "from": 1000, "until": 300000}

test_a_lease_admits_inside_its_window_and_horizon if {
	edge.admit.allow with input as {"person": "idp:7c1f-ann", "target": "plc-ssh", "now": 2000, "issued": 1500, "leases": [lease], "visit_leases": [], "revoked": []}
}

test_past_the_privileged_horizon_the_lease_no_longer_admits if {
	not edge.admit.allow with input as {"person": "idp:7c1f-ann", "target": "plc-ssh", "now": 9000, "issued": 1500, "leases": [lease], "visit_leases": [], "revoked": []}
}

test_a_visit_lease_keeps_its_own_window_past_the_horizon if {
	edge.admit.allow with input as {"person": "idp:7c1f-ann", "target": "plc-ssh", "now": 200000, "issued": 1500, "leases": [lease], "visit_leases": [visit], "revoked": []}
}

test_a_revoked_lease_never_admits if {
	not edge.admit.allow with input as {"person": "idp:7c1f-ann", "target": "plc-ssh", "now": 2000, "issued": 1500, "leases": [lease], "visit_leases": [], "revoked": ["L-1"]}
}

test_the_visit_window_is_capped_by_policy_and_by_the_ceiling if {
	edge.visit_window.allow with input as {"hours": 48, "max_offline_hours": 72}
	not edge.visit_window.allow with input as {"hours": 96, "max_offline_hours": 200}
	not edge.visit_window.allow with input as {"hours": 48, "max_offline_hours": 24}
}

c := {"persons": ["idp:7c1f-ann"], "roles": ["operators"], "targets": ["plc-ssh"], "classes": ["low", "elevated"], "max_lease_hours": 8, "max_offline_hours": 72, "profile": "assured"}

test_the_ceiling_allows_what_it_names if {
	ceiling.decision.allow with input as {"ceiling": c, "entry": {"kind": "lease", "person": "idp:7c1f-ann", "targets": ["plc-ssh"], "class": "low", "hours": 4}}
}

test_the_ceiling_refuses_a_class_a_target_and_a_length_it_does_not_name if {
	d := ceiling.decision with input as {"ceiling": c, "entry": {"kind": "lease", "person": "idp:0000-x", "targets": ["db"], "class": "privileged", "hours": 9}}
	not d.allow
	count(d.refusals) == 4
}

test_a_visit_needs_an_assured_attested_edge if {
	not ceiling.decision.allow with input as {"ceiling": c, "entry": {"kind": "visit", "person": "idp:7c1f-ann", "targets": ["plc-ssh"], "hours": 24, "attested_profile": "basic"}}
	ceiling.decision.allow with input as {"ceiling": c, "entry": {"kind": "visit", "person": "idp:7c1f-ann", "targets": ["plc-ssh"], "hours": 24, "attested_profile": "assured"}}
}

test_a_role_never_admits_an_elevated_lease if {
	d := ceiling.decision with input as {"ceiling": c, "entry": {"kind": "lease", "person": "idp:1111-bo", "roles": ["operators"], "targets": ["plc-ssh"], "class": "elevated", "hours": 4}}
	not d.allow
}
