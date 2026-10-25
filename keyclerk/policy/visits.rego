# Visits (decision 0009, sections 1, 2 and 4). The engine evaluates it compiled to WebAssembly (keyclerk.policy_wasm);
# code gathers the facts, this file decides. Times are whole seconds since the epoch, so no time builtin is needed.
#
# Four decisions:
#   act     may this person take this visit action now
#   entry   may this party pass this checkpoint now, and on what conditions (escort, front office, badge)
#   timers  which steps are due now; each step re-checks, when it fires, that its reason still holds
#   see     may this viewer see this visit
#   unescorted  the answer to anyone who scans a guest's QR code with a phone: yes or no, and until when
#   badge   may this badge be issued: a visitor badge by the front office, a RESTRICTED badge also with a second key
package keyclerk.visits

import rego.v1

# --- act ---------------------------------------------------------------------------------------------------------
# input: {action, actor: {anchor, is_host, is_organiser, front_office, steward, kind}, visit: {host_kind}}

default act := {"allow": false, "reasons": ["this action is not open to you on this visit"]}

host_or_organiser if input.actor.is_host

host_or_organiser if input.actor.is_organiser

# escorts accompany the guests: they acknowledge and confirm like the host
receiving if host_or_organiser

receiving if input.actor.is_escort

place_staff if input.actor.front_office

place_staff if input.actor.steward

act := {"allow": true, "reasons": []} if {
	input.action == "register_visit"
	host_or_organiser
	input.visit.host_kind == "tenant"
}

act := {"allow": false, "reasons": ["the host of a visit is someone of the tenant who receives the guest"]} if {
	input.action == "register_visit"
	host_or_organiser
	input.visit.host_kind != "tenant"
}

act := {"allow": false, "reasons": ["only the host or the organiser registers a visit"]} if {
	input.action == "register_visit"
	not host_or_organiser
}

act := {"allow": true, "reasons": []} if {
	input.action in {"record_entry", "record_departure", "issue_badge", "return_badge"}
	place_staff
}

act := {"allow": true, "reasons": []} if {
	input.action in {"acknowledge_arrival", "confirm_guest"}
	receiving
}

# someone not on the list turns up: the host, the organiser or the front office adds them (decision 0010)
act := {"allow": true, "reasons": []} if {
	input.action == "add_attendee"
	host_or_organiser
}

act := {"allow": true, "reasons": []} if {
	input.action == "add_attendee"
	not host_or_organiser
	place_staff
}

# an invited or unregistered attendee registered at the front office, identity checked there
act := {"allow": true, "reasons": []} if {
	input.action == "register_on_site"
	place_staff
}

act := {"allow": true, "reasons": []} if {
	input.action == "record_departure"
	host_or_organiser
}

# a new QR code (the old one stops working): the host, the organiser or the guest themselves
act := {"allow": true, "reasons": []} if {
	input.action == "issue_qr"
	host_or_organiser
}

act := {"allow": true, "reasons": []} if {
	input.action == "issue_qr"
	not host_or_organiser
	input.actor.is_party
}

# --- entry -------------------------------------------------------------------------------------------------------
# input: {now, visit: {opens, closes, ended}, party: {registered, role, suspended, departed},
#         zone: null | {zone_id, badge: "restricted" | null}, presented: "qr" | "visitor-badge" | "restricted-badge" | "none",
#         vehicle: bool}

e := input

opens := e.visit.opens

closes := e.visit.closes

needs_restricted if e.zone.badge == "restricted"

entry_refusal contains "this visit has ended" if e.visit.ended

entry_refusal contains "access is suspended: the front office decides what happens next" if e.party.suspended

entry_refusal contains "already left: a new visit is needed to come back" if e.party.departed

entry_refusal contains "too early: the visit window has not opened yet" if e.now < opens

entry_refusal contains "the visit window has closed" if e.now >= closes

# a badge shown at the gate counts only when it was issued to this party and holds now (unless not required)
entry_refusal contains "no visitor badge was issued to this guest, or it no longer holds" if {
	e.presented == "visitor-badge"
	e.badges.required
	not e.badges.visitor
}

entry_refusal contains "no RESTRICTED badge was issued to this guest, or it no longer holds" if {
	e.presented == "restricted-badge"
	e.badges.required
	not e.badges.restricted
}

# a QR counts only when the desk checked the code online (unless the configuration does not require one)
entry_refusal contains concat(": ", ["the QR code does not check out", e.qr.problem]) if {
	e.presented == "qr"
	e.qr.required
	not e.qr.valid
}

entry_refusal contains "a vehicle comes in only with a registered driver" if {
	e.vehicle
	not e.party.registered
}

stopped if count(entry_refusal) > 0

# an unregistered passenger can never receive a RESTRICTED badge: no identity, no claims
never if {
	needs_restricted
	not e.party.registered
}

entry := {
	"allow": false, "never": false, "escort": false, "front_office": false, "badge": null,
	"until": closes, "reasons": sort(entry_refusal),
} if stopped

else := {
	"allow": false, "never": true, "escort": false, "front_office": false, "badge": null, "until": closes,
	"reasons": ["an unregistered passenger can never receive a RESTRICTED badge"],
} if {
	never
}

else := {
	"allow": true, "never": false, "escort": false, "front_office": false, "badge": "restricted", "until": closes,
	"reasons": [],
} if {
	needs_restricted
	e.presented == "restricted-badge"
}

else := {
	"allow": false, "never": false, "escort": false, "front_office": true, "badge": "restricted", "until": closes,
	"reasons": ["this zone needs a RESTRICTED badge: collect it at the front office (a second person signs it out)"],
} if {
	needs_restricted
}

else := {
	"allow": true, "never": false, "escort": false, "front_office": false, "badge": null, "until": closes,
	"reasons": [],
} if {
	e.party.registered
	e.presented in {"qr", "restricted-badge"}
}

else := {
	"allow": true, "never": false, "escort": true, "front_office": false, "badge": "visitor", "until": closes,
	"reasons": ["escorted: a temporary visitor badge"],
} if {
	e.presented == "visitor-badge"
}

else := {
	"allow": false, "never": false, "escort": false, "front_office": true, "badge": "visitor", "until": closes,
	"reasons": ["wait at the front office for a temporary visitor badge"],
} if {
	not e.party.registered
}

else := {
	"allow": false, "never": false, "escort": false, "front_office": true, "badge": null, "until": closes,
	"reasons": ["show the QR code from registration, or identify at the front office"],
}

# --- timers ------------------------------------------------------------------------------------------------------
# input: {now, confirm_after, grace, parties: [{visit_id, party, arrived, acknowledged, confirmed, reminded,
#         departed, suspended, closes}]}
# A reminder is due confirm_after seconds after arrival; a suspension grace seconds later. Each fires only while its
# reason holds: not confirmed, not left, not already suspended, the visit not over.

open_reason(p) if {
	not p.confirmed
	not p.departed
	not p.suspended
	input.now < p.closes
}

due contains {
	"visit_id": p.visit_id, "party": p.party, "step": "remind",
	"reason": "the host has not confirmed that the guest is with them",
} if {
	some p in input.parties
	open_reason(p)
	not p.reminded
	input.now >= p.arrived + input.confirm_after
	input.now < (p.arrived + input.confirm_after) + input.grace
}

due contains {
	"visit_id": p.visit_id, "party": p.party, "step": "suspend",
	"reason": "no confirmation that the guest is with the host: access suspended and flagged for the officer",
} if {
	some p in input.parties
	open_reason(p)
	input.now >= (p.arrived + input.confirm_after) + input.grace
}

timers := sort(due)

# --- see ---------------------------------------------------------------------------------------------------------
# input: {viewer: {all, is_host, is_organiser, front_office, steward, is_party}}

default see := false

see if input.viewer.all

see if input.viewer.is_host

see if input.viewer.is_organiser

see if input.viewer.front_office

see if input.viewer.steward

see if input.viewer.is_party

see if input.viewer.is_escort

# --- unescorted --------------------------------------------------------------------------------------------------
# input: {now, code: {valid}, visit: {opens, closes}, party: {registered, arrived, suspended, departed}}
# Only yes or no and until when: no name, no purpose, no host. Yes needs a current code, a registered guest who
# passed the gate, not suspended, not left, inside the window.

default unescorted := {"unescorted": false, "until": null}

unescorted := {"unescorted": true, "until": input.visit.closes} if {
	input.code.valid
	input.party.registered
	input.party.arrived
	not input.party.suspended
	not input.party.departed
	input.visit.opens <= input.now
	input.now < input.visit.closes
}

# --- badge -------------------------------------------------------------------------------------------------------
# input: {badge: {kind, from, to}, visit: {opens, closes}, party: {registered, suspended, departed},
#         issuer: {front_office, steward}, seconds: [{front_office, steward, is_issuer}]}
# Judged as made (at the badge's from), so a later change never rewrites whether it was issued rightly.

b := input.badge

badge_refusal contains "an unregistered passenger can never receive a RESTRICTED badge" if {
	b.kind == "restricted"
	not input.party.registered
}

badge_refusal contains "only the front office or the steward of the place issues badges" if {
	not input.issuer.front_office
	not input.issuer.steward
}

badge_refusal contains "the guest is suspended or has left" if input.party.suspended

badge_refusal contains "the guest is suspended or has left" if input.party.departed

badge_refusal contains "a badge holds only inside the visit window" if b.from < input.visit.opens

badge_refusal contains "a badge holds only inside the visit window" if b.to > input.visit.closes

badge_refusal contains "a badge ends after it starts" if b.to <= b.from

second_key if {
	some s in input.seconds
	not s.is_issuer
	s.front_office
}

second_key if {
	some s in input.seconds
	not s.is_issuer
	s.steward
}

badge_refusal contains "a RESTRICTED badge needs a second key from another front office person or the steward of the place" if {
	b.kind == "restricted"
	input.party.registered
	not second_key
}

badge := sort(badge_refusal)
