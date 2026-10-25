package keyclerk.visits_test

import rego.v1

import data.keyclerk.visits

# the meeting is 13:00 to 14:00 with two hours either side: opens 11:00 (39600), closes 16:00 (57600)
visit := {"opens": 39600, "closes": 57600, "ended": false}

driver := {"registered": true, "role": "driver", "suspended": false, "departed": false}

passenger := {"registered": false, "role": "passenger", "suspended": false, "departed": false}

restricted := {"zone_id": "zone:lab", "badge": "restricted"}

ask(party, zone, presented, vehicle, now) := d if {
	d := visits.entry with input as {
		"now": now, "visit": visit, "party": party, "zone": zone, "presented": presented, "vehicle": vehicle,
		"qr": {"required": true, "valid": true, "problem": ""},
		"badges": {"required": true, "visitor": true, "restricted": true},
	}
}

test_the_driver_enters_with_the_qr_and_the_vehicle_inside_the_window if {
	d := ask(driver, null, "qr", true, 39600)
	d.allow
	not d.escort
}

test_not_before_the_window_opens if {
	d := ask(driver, null, "qr", true, 39599)
	not d.allow
	count(d.reasons) == 1
}

test_the_unregistered_passenger_waits_for_a_visitor_badge if {
	d := ask(passenger, null, "none", false, 40000)
	not d.allow
	d.front_office
	d.badge == "visitor"
	e := ask(passenger, null, "visitor-badge", false, 40000)
	e.allow
	e.escort
}

test_a_passenger_does_not_take_the_vehicle_through if {
	d := ask(passenger, null, "visitor-badge", true, 40000)
	not d.allow
}

test_a_restricted_zone_sends_the_driver_to_the_front_office if {
	d := ask(driver, restricted, "qr", false, 40000)
	not d.allow
	d.front_office
	d.badge == "restricted"
	ask(driver, restricted, "restricted-badge", false, 40000).allow
}

test_the_unregistered_passenger_can_never_get_a_restricted_badge if {
	d := ask(passenger, restricted, "visitor-badge", false, 40000)
	not d.allow
	d.never
}

test_a_suspended_party_is_stopped if {
	d := ask(object.union(driver, {"suspended": true}), null, "qr", false, 40000)
	not d.allow
	not d.front_office
}

arrived := {
	"visit_id": "V-1", "party": "P1", "arrived": 40000, "acknowledged": true, "confirmed": false,
	"reminded": false, "departed": false, "suspended": false, "closes": 57600,
}

due(p, now) := d if {
	d := visits.timers with input as {"now": now, "confirm_after": 900, "grace": 300, "parties": [p]}
}

test_nothing_is_due_before_fifteen_minutes if {
	due(arrived, 40899) == []
}

test_a_reminder_after_fifteen_minutes if {
	[d] := due(arrived, 40900)
	d.step == "remind"
}

test_suspension_five_minutes_later if {
	[d] := due(object.union(arrived, {"reminded": true}), 41200)
	d.step == "suspend"
}

test_each_step_rechecks_its_reason if {
	due(object.union(arrived, {"confirmed": true}), 41200) == []
	due(object.union(arrived, {"departed": true}), 41200) == []
	due(object.union(arrived, {"suspended": true}), 41200) == []
	due(arrived, 57600) == []
}

test_who_may_act if {
	visits.act.allow with input as {"action": "register_visit", "actor": {"is_host": true}, "visit": {"host_kind": "tenant"}}
	not visits.act.allow with input as {"action": "register_visit", "actor": {"is_host": true}, "visit": {"host_kind": "external"}}
	not visits.act.allow with input as {"action": "register_visit", "actor": {}, "visit": {"host_kind": "tenant"}}
	visits.act.allow with input as {"action": "record_entry", "actor": {"front_office": true}}
	not visits.act.allow with input as {"action": "record_entry", "actor": {"is_host": true}}
	visits.act.allow with input as {"action": "confirm_guest", "actor": {"is_organiser": true}}
	not visits.act.allow with input as {"action": "confirm_guest", "actor": {"front_office": true}}
}

test_who_may_see if {
	visits.see with input as {"viewer": {"is_party": true}}
	not visits.see with input as {"viewer": {}}
}

test_a_qr_that_did_not_check_out_does_not_count if {
	d := visits.entry with input as {
		"now": 40000, "visit": visit, "party": driver, "zone": null, "presented": "qr", "vehicle": false,
		"qr": {"required": true, "valid": false, "problem": "the code has expired"},
	}
	not d.allow
	d.reasons == ["the QR code does not check out: the code has expired"]
	e := visits.entry with input as {
		"now": 40000, "visit": visit, "party": driver, "zone": null, "presented": "qr", "vehicle": false,
		"qr": {"required": false, "valid": false, "problem": ""},
	}
	e.allow
}

inside := {"registered": true, "arrived": true, "suspended": false, "departed": false}

scan(party, valid, now) := d if {
	d := visits.unescorted with input as {"now": now, "code": {"valid": valid}, "visit": visit, "party": party}
}

test_the_phone_scan_says_yes_only_for_a_checked_in_guest_with_a_current_code if {
	scan(inside, true, 40000) == {"unescorted": true, "until": 57600}
	not scan(inside, false, 40000).unescorted
	not scan(object.union(inside, {"arrived": false}), true, 40000).unescorted
	not scan(object.union(inside, {"suspended": true}), true, 40000).unescorted
	not scan(object.union(inside, {"departed": true}), true, 40000).unescorted
	not scan(object.union(inside, {"registered": false}), true, 40000).unescorted
	not scan(inside, true, 57600).unescorted
}

test_issuing_a_new_code if {
	visits.act.allow with input as {"action": "issue_qr", "actor": {"is_party": true}}
	visits.act.allow with input as {"action": "issue_qr", "actor": {"is_host": true}}
	not visits.act.allow with input as {"action": "issue_qr", "actor": {"front_office": true}}
}

bdg(kind, party, issuer, seconds) := d if {
	d := visits.badge with input as {
		"badge": {"kind": kind, "from": 40000, "to": 57600}, "visit": visit, "party": party,
		"issuer": issuer, "seconds": seconds,
	}
}

fo := {"front_office": true, "steward": false}

test_a_visitor_badge_from_the_front_office if {
	bdg("visitor", passenger, fo, []) == []
	bdg("visitor", passenger, {"front_office": false, "steward": false}, []) != []
}

test_a_restricted_badge_waits_for_a_second_key if {
	bdg("restricted", driver, fo, []) == ["a RESTRICTED badge needs a second key from another front office person or the steward of the place"]
	bdg("restricted", driver, fo, [object.union(fo, {"is_issuer": true})]) != []
	bdg("restricted", driver, fo, [object.union(fo, {"is_issuer": false})]) == []
	bdg("restricted", driver, fo, [{"front_office": false, "steward": true, "is_issuer": false}]) == []
}

test_never_a_restricted_badge_for_an_unregistered_passenger if {
	bdg("restricted", passenger, fo, [object.union(fo, {"is_issuer": false})]) == ["an unregistered passenger can never receive a RESTRICTED badge"]
}

test_a_badge_shown_at_the_gate_must_hold if {
	d := visits.entry with input as {
		"now": 40000, "visit": visit, "party": passenger, "zone": null, "presented": "visitor-badge", "vehicle": false,
		"qr": {"required": true, "valid": false, "problem": ""},
		"badges": {"required": true, "visitor": false, "restricted": false},
	}
	not d.allow
}

test_people_first if {
	visits.act.allow with input as {"action": "confirm_guest", "actor": {"is_escort": true}}
	visits.act.allow with input as {"action": "add_attendee", "actor": {"front_office": true}}
	visits.act.allow with input as {"action": "register_on_site", "actor": {"front_office": true}}
	not visits.act.allow with input as {"action": "register_on_site", "actor": {"is_host": true}}
	visits.see with input as {"viewer": {"is_escort": true}}
}
