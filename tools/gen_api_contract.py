# SPDX-License-Identifier: EUPL-1.2
"""Write keyclerk/schema/api.openapi.json: the contract of the KeyClerk API (v1), from the definitions below.

    python tools/gen_api_contract.py           write it
    python tools/gen_api_contract.py --check   exit 1 when the committed contract differs (a test runs this too)
"""
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "keyclerk" / "schema" / "api.openapi.json"

ID = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,255}$"}
ANCHOR = {"type": "string", "pattern": "^(?![uU][iI][dD]:)[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,255}$"}
TIME = {"type": "string", "format": "date-time"}
RISK = {"enum": ["low", "elevated", "privileged"]}
POWER = {"enum": ["delegate", "includes", "members", "rules", "subgroups"]}
NULLS = lambda s: {"anyOf": [s, {"type": "null"}]}   # noqa: E731
TEXT = {"type": "string", "maxLength": 300}


def obj(props: dict, required=None, extra=False):
    return {"type": "object", "required": sorted(required if required is not None else props),
            "additionalProperties": extra, "properties": props}


def d(schema, text):
    """A schema with a description: the contract explains itself to every front end, the bundled API page included."""
    return {**schema, "description": text}


def ref(name):
    return {"$ref": f"#/components/schemas/{name}"}


def arr(s, max_items=10000):
    return {"type": "array", "items": s, "maxItems": max_items}


NEXT = {"type": "array", "maxItems": 10, "description": "what would complete the intent: why, what to do, who can do it",
        "items": {"type": "object", "required": ["why", "do", "who"], "additionalProperties": False,
                  "properties": {"why": TEXT, "do": TEXT,
                                 "who": {"type": "array", "maxItems": 50,
                                         "items": {"type": "object", "required": ["anchor", "name"], "additionalProperties": False,
                                                   "properties": {"anchor": ANCHOR, "name": NULLS(TEXT)}}}}}}
S = {
    "Error": obj({"error": obj({"code": {"enum": ["unauthenticated", "forbidden", "not_found", "refused", "invalid",
                                                   "busy", "too_large", "unsupported_media", "csrf", "not_allowed",
                                                   "rate_limited", "internal"],
                                          "x-meanings": {
                                              "unauthenticated": "not signed in, or the bearer token is not valid here",
                                              "forbidden": "signed in, but this view or action is not yours",
                                              "not_found": "no such call, group, person or change",
                                              "refused": "the desk or the engine said no; the message says why",
                                              "invalid": "the request does not match the contract",
                                              "busy": "every worker is busy; try again shortly",
                                              "too_large": "the body is above 64 KiB",
                                              "unsupported_media": "send application/json",
                                              "csrf": "a browser session must send X-KeyClerk-CSRF from /me, from this site",
                                              "not_allowed": "this method is not offered on this path",
                                              "rate_limited": "too many requests from one person: 30 changes in 10 minutes, 4 requests at once",
                                              "internal": "a fault on the server; nothing was changed by it"}},
                                "message": TEXT, "next": NEXT}, ["code", "message"])}),
    "Entitlement": obj({"entitlement": ID, "via": arr(ID)}),
    "Delegation": obj({
        "delegation_id": ID, "delegate": ANCHOR, "delegate_name": NULLS(TEXT), "group": ID, "powers": arr(POWER, 5),
        "max_risk": RISK, "max_membership_days": {"type": "integer"}, "depth_left": {"type": "integer"},
        "place": NULLS(ID), "start": TIME, "end": TIME, "by": ANCHOR, "by_name": NULLS(TEXT), "parent": ID,
        "approved_by": arr(ANCHOR), "status": {"enum": ["ok", "grace", "dead"]}, "grace_until": NULLS(TIME),
        "chain": arr(ID), "can_end": {"type": "boolean"},
        "impact": obj({"delegations": arr(ID), "memberships": arr(ID)})}),
    "Me": obj({
        "anchor": NULLS(ANCHOR), "name": NULLS(TEXT), "person": NULLS(TEXT), "kind": NULLS(TEXT), "roles": arr(ID, 64),
        "viewer": {"type": "boolean"}, "root": {"type": "boolean"}, "realm": ID, "revision": {"type": "integer"},
        "delegations": arr(ref("Delegation")), "manages": arr(obj({"group": ID, "powers": arr(POWER, 5)})),
        "entitlements": arr(ref("Entitlement")), "waiting_for_me": {"type": "integer"},
        "guests_waiting": d({"type": "integer"}, "arrived guests you host or organise and still have to acknowledge or confirm"),
        "csrf": NULLS({"type": "string", "maxLength": 64}),
        "approval_sign_in": d({"type": "boolean"}, "true: approving means signing in again at the broker (decision 0006)"),
        "account_url": NULLS(d({"type": "string", "pattern": "^https?://", "maxLength": 2048},
                               "where a person manages how they sign in, such as registering a passkey"))}),
    "Person": obj({"anchor": ANCHOR, "person": TEXT, "kind": {"enum": ["tenant", "external", "agent"]}}),
    "PersonAccess": obj({"anchor": ANCHOR, "person": TEXT, "kind": {"enum": ["tenant", "external", "agent"]},
                         "groups": arr(obj({"group": ID, "paths": arr(arr(TEXT))})),
                         "entitlements": arr(ref("Entitlement")), "delegations": arr(ref("Delegation"))}),
    "GraphNode": obj({"id": TEXT, "kind": d({"enum": ["subject", "account", "person", "group", "scope", "place"]},
                                            "subject: the person asked about; account: one of their anchors, with its "
                                            "identity source; scope: a top part of the group tree, drawn as a box"),
                      "label": TEXT}, extra=True),
    "GraphEdge": obj({"id": TEXT, "kind": d({"type": "string", "maxLength": 40},
                                            "account, member, added, approved, manages, delegated, approver, steward, "
                                            "deputy, front_office, lease, sponsor, within"),
                      "source": TEXT, "target": TEXT, "label": TEXT, "from": NULLS(TIME), "to": NULLS(TIME),
                      "status": NULLS(TEXT)}, extra=True),
    "TreeNode": obj({"id": TEXT, "kind": d({"enum": ["root", "delegation"]}, "root: the root holder at the moment"),
                     "label": TEXT, "parent": NULLS(TEXT),
                     "status": d({"type": "string", "maxLength": 20},
                                 "pending, active, grace, ended, revoked, or dead (a link above it broke)")}, extra=True),
    "DelegationTree": obj({"at": TIME, "nodes": arr(ref("TreeNode"), 5000),
                           "edges": arr(obj({"id": TEXT, "source": TEXT, "target": TEXT, "status": TEXT}), 5000),
                           "marks": d(obj({"before": arr(TIME, 20), "after": arr(TIME, 20)}),
                                      "the moments just before and after `at` where a delegation starts or stops"),
                           "whole": d({"type": "boolean"}, "true for a viewer or the root: the whole tree"),
                           "held": d(arr(ID), "the delegations you hold or held, in the tree")}),
    "VisitSummary": obj({"visit_id": ID, "place": TEXT, "place_name": TEXT, "host": ANCHOR, "host_name": NULLS(TEXT),
                         "organiser": ANCHOR, "organiser_name": NULLS(TEXT), "purpose": TEXT, "start": TIME, "end": TIME,
                         "opens": TIME, "closes": TIME, "when": {"enum": ["upcoming", "open", "closed"]},
                         "parties": {"type": "integer"}, "unregistered": {"type": "integer"}, "vehicles": arr(TEXT, 4),
                         "suspended": {"type": "integer"},
                         "waiting_for_me": d({"type": "integer"}, "arrived guests you still have to acknowledge or confirm")}),
    "VisitDetail": obj({"visit_id": ID, "at": TIME, "zones": arr(ID, 10),
                        "parties": arr(obj({"party": ID, "role": TEXT, "registered": {"type": "boolean"}, "name": TEXT,
                                            "arrived": NULLS(TIME), "gate": d({"type": "object"}, "what the entry policy says now"),
                                            "actions": d(arr(TEXT, 4), "what you may record for this party now")}, extra=True), 12),
                        "timeline": d(arr(obj({"at": TIME, "kind": TEXT, "text": TEXT}, extra=True), 500),
                                      "the window, what happened and the timer steps ahead (each re-checks its reason)")},
                       extra=True),
    "PersonGraph": obj({"subject": ANCHOR, "at": TIME, "nodes": arr(ref("GraphNode"), 2000), "edges": arr(ref("GraphEdge"), 5000),
                        "marks": d(obj({"before": arr(TIME, 20), "after": arr(TIME, 20)}),
                                   "the moments just before and after `at` where something in the graph starts or ends"),
                        "realm_sources": NULLS(d(arr(obj({"id": TEXT, "name": TEXT, "kind": TEXT, "persons": {"type": "integer"},
                                                          "accounts": {"type": "integer"}}), 100),
                                                 "for a viewer or the root: the identity sources the realm's people come "
                                                 "through"))}),
    "Group": obj({"group_id": ID, "parent": NULLS(ID), "depth": {"type": "integer"}, "max_risk": RISK,
                  "effective_risk": RISK, "place": NULLS(ID), "description": NULLS(TEXT), "carries": arr(ID),
                  "members": {"type": "integer"}, "my_powers": arr(POWER, 5)}),
    "Membership": obj({"membership_id": ID, "kind": {"enum": ["anchor", "group", "rule"]}, "member": ID,
                       "member_name": NULLS(TEXT), "by": ANCHOR, "by_name": NULLS(TEXT), "under": ID, "chain": arr(ID),
                       "approved_by": arr(ANCHOR), "start": TIME, "end": TIME,
                       "status": {"enum": ["active", "pending", "ended", "revoked", "void", "lapsed", "invalid", "standby"]},
                       "can_end": {"type": "boolean"}}),
    "Manager": obj({"anchor": NULLS(ANCHOR), "name": NULLS(TEXT), "delegation_id": ID, "over": ID, "powers": arr(POWER, 5),
                    "status": {"enum": ["ok", "grace", "dead"]}, "chain": arr(ID)}),
    "GroupDetail": obj({
        "group_id": ID, "parent": NULLS(ID), "ancestors": arr(ID), "children": arr(ID), "max_risk": RISK,
        "effective_risk": RISK, "place": NULLS(ID), "description": NULLS(TEXT), "carries": arr(ID),
        "included_by": arr(ID), "memberships": arr(ref("Membership")),
        "effective_members": arr(obj({"anchor": ANCHOR, "name": NULLS(TEXT), "paths": arr(arr(TEXT)),
                                      "in_broker": NULLS({"type": "boolean"})})),
        "managers": arr(ref("Manager")), "my_powers": arr(POWER, 5)}),
    "PendingChange": obj({"change_id": ID, "summary": TEXT, "action": ID, "actor": ANCHOR, "actor_name": NULLS(TEXT),
                          "at": TIME, "reasons": arr(TEXT, 50), "expired": {"type": "boolean"},
                          "approvals": arr(ANCHOR, 20),
                          "needs": d(arr(TEXT, 5), "what it waits for, in plain words"),
                          "waiting_for": d(arr(obj({"anchor": ANCHOR, "name": NULLS(TEXT)}), 50),
                                           "who could add the key it still needs"),
                          "can_approve": {"type": "boolean"}, "can_withdraw": {"type": "boolean"}, "can_sign": {"type": "boolean"},
                          "what": d(arr(ref("ChangeLine"), 20), "what it changes, one line per record: check it before you sign"),
                          "approval_names": arr(NULLS(TEXT), 20)}),
    "ChangeLine": obj({"kind": TEXT, "group": NULLS(ID), "risk": NULLS(TEXT), "member": NULLS(ANCHOR), "member_name": NULLS(TEXT),
                       "start": NULLS(TIME), "end": NULLS(TIME), "detail": NULLS(TEXT),
                       "under": d(NULLS(TEXT), "the delegation chain it is made under, up to the root")}),
    "LogEntry": {"type": "object", "required": ["seq", "at", "outcome", "sha256", "prev"],
                 "properties": {"seq": {"type": "integer"}, "at": TIME, "outcome": {"enum": ["applied", "pending", "refused", "withdrawn", "recovered"]},
                                "sha256": {"type": "string"}, "prev": {"type": "string"},
                                "action": d(NULLS(TEXT), "what was asked"), "summary": NULLS(TEXT),
                                "actor": NULLS(ANCHOR), "actor_name": NULLS(TEXT),
                                "approved_by": NULLS(ANCHOR), "approver_name": NULLS(TEXT),
                                "reasons": arr(TEXT, 50), "revision": {"type": "integer"}, "change_id": NULLS(ID)},
                 "additionalProperties": True},
    "Changes": obj({"pending": arr(ref("PendingChange")), "log": arr(ref("LogEntry"))}),
    "PersonKey": obj({"key_id": ID, "public_key": TEXT, "ssh_key": NULLS({"type": "string", "maxLength": 900}), "at": TIME,
                      "credential_id": NULLS({"type": "string", "maxLength": 400}),
                      "active": {"type": "boolean"}}),
    "RelayItem": obj({"relay_id": ID, "edge": ID, "key_id": ID, "purpose": TEXT, "created": TIME, "expires": NULLS(TIME),
                      "taken": NULLS(TIME)}),
    "RelayTaken": obj({"relay_id": ID, "key_id": ID, "purpose": TEXT,
                       "envelope": d(obj({"format": {"const": "kc-relay-v1"}, "epk": TEXT, "nonce": TEXT,
                                          "ct": {"type": "string", "maxLength": 8192}, "context": TEXT}),
                                     "X25519 + HKDF-SHA256 + AES-256-GCM to your person key (keyclerk/relay.py)")}),
    "SignedCeiling": obj({"ceiling": d(obj({"bytes": {"type": "string", "maxLength": 65536},
                                            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
                                            "key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                                            "key_id": {"type": "string", "pattern": "^[0-9a-f]{16}$"}},
                                           ["bytes", "signature", "key", "key_id"]),
                                       "kc-edge-ceiling-v2: the ceiling sealed by the officer (python -m keyclerk.edge_cli seal); "
                                       "the bundle carries these bytes as they are (amendment 0014d)")}, ["ceiling"]),
    "ChangeResult": obj({"change_id": ID, "outcome": {"enum": ["applied", "pending", "refused", "withdrawn"]},
                         "summary": TEXT, "reasons": arr(TEXT, 50), "records": {"type": "object"},
                         "revision": {"type": "integer"}, "next": NEXT}, ["change_id", "outcome", "summary", "reasons", "records", "revision"]),
    "SignIn": obj({"redirect": d({"type": "string", "pattern": "^https?://", "maxLength": 4096}, "go here to sign in and approve")}),
    "Statement": obj({"change_id": ID, "nonce": d({"type": "string", "maxLength": 64}, "the OIDC nonce to sign in with"),
                      "summary": TEXT,
                      "records": arr(ID, 20), "by": ANCHOR,
                      "required": d({"type": "boolean"}, "whether this desk accepts an approval only with a proof"),
                      "purpose": d({"enum": ["approval", "proposal"]},
                                   "approval, or proposal: the proposer signs their own high-risk change (decision 0015)")}),
    "PhoneLink": obj({"change_id": ID, "url": d({"type": "string", "maxLength": 2048}, "open it on the other device"),
                      "qr": d({"type": "string", "pattern": "^/approve-qr/", "maxLength": 2048}, "the same link as a QR image, on this desk"),
                      "expires_at": TIME}),
    "ApproveRequest": obj({"proof": d({"type": "string", "maxLength": 16384},
                                      "the ID token the broker issued after a fresh sign-in with the statement's nonce")}, []),
    "Preview": obj({"outcome": {"enum": ["applied", "pending", "refused"]}, "summary": TEXT, "reasons": arr(TEXT, 50),
                    "records": {"type": "object"}, "revision": {"type": "integer"}, "next": NEXT}),
    "Broker": obj({"revision": {"type": "integer"}, "observed": {"type": "integer"},
                   "runs": arr({"type": "object"}, 20), "log_intact": {"type": "boolean"},
                   "manual_changes": arr(obj({"at": NULLS(TEXT), "group": TEXT, "member": TEXT, "member_name": NULLS(TEXT),
                                              "by": TEXT, "client": TEXT}), 50)}),
}

DAYS = {"type": "integer", "minimum": 1, "maximum": 3650}
REQ = {
    "add_member": d(obj({"action": {"const": "add_member"}, "group": d(ID, "the group to add to (you need the members power over it)"),
                         "anchor": d(ANCHOR, "the person, by anchor"),
                         "days": d(DAYS, "how long; at most what your delegation allows")}, ["action", "group", "anchor"]),
                    "Add a person to a group"),
    "include_group": d(obj({"action": {"const": "include_group"}, "group": d(ID, "the group that includes (the includes power)"),
                            "include": d(ID, "the group whose members join it; its manager's key may be needed"),
                            "days": d(DAYS, "how long")}, ["action", "group", "include"]),
                       "Nest a group in another"),
    "end_membership": d(obj({"action": {"const": "end_membership"}, "membership_id": d(ID, "the membership to end"),
                             "reason": d(TEXT, "why; kept in the records (3 characters or more)")},
                            ["action", "membership_id", "reason"]),
                        "End a membership or a nesting"),
    "create_group": d(obj({"action": {"const": "create_group"}, "parent": d(ID, "the group to create it under (the subgroups power)"),
                           "group_id": d({"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{1,62}$"}, "lower case letters, digits and dashes"),
                           "max_risk": d(RISK, "its class; not above your delegation's"),
                           "description": d(TEXT, "one line")}, ["action", "parent", "group_id"]),
                      "Create a subgroup"),
    "delegate": d(obj({"action": {"const": "delegate"}, "group": d(ID, "the subtree you hand on (the delegate power)"),
                       "delegate": d(ANCHOR, "who receives it"),
                       "powers": d({"type": "array", "items": POWER, "minItems": 1, "maxItems": 5, "uniqueItems": True},
                                   "a subset of your own powers"),
                       "max_risk": d(RISK, "the highest class they may act on; not above yours"),
                       "max_membership_days": d(DAYS, "the longest membership they may grant"),
                       "depth_left": d({"type": "integer", "minimum": 0, "maximum": 5}, "how many times they may delegate again"),
                       "days": d(DAYS, "how long the delegation lasts")}, ["action", "group", "delegate", "powers"]),
                  "Delegate part of what you hold"),
    "end_delegation": d(obj({"action": {"const": "end_delegation"}, "delegation_id": d(ID, "the delegation to end"),
                             "mode": d({"enum": ["retire", "revoke"]}, "retire: orderly, with a grace period; revoke: for cause"),
                             "reason": d(TEXT, "why; kept in the records")}, ["action", "delegation_id", "reason"]),
                        "End a delegation"),
    "appoint_approver": d(obj({"action": {"const": "appoint_approver"}, "anchor": d(ANCHOR, "who may give second keys"),
                               "days": d(DAYS, "how long; at most the configured maximum"),
                               "reason": d(TEXT, "why; kept in the records")}, ["action", "anchor", "reason"]),
                          "Appoint a named approver (the root; waits for the security officer's key)"),
    "end_approver": d(obj({"action": {"const": "end_approver"}, "approver_id": d(ID, "the appointment to end"),
                           "reason": d(TEXT, "why; kept in the records")}, ["action", "approver_id", "reason"]),
                      "End a named approver's appointment (the root or the security officer)"),
    "register_visit": d(obj({
        "action": {"const": "register_visit"}, "place": d(ID, "the place visited (a site or a place within one)"),
        "host": d(ANCHOR, "who receives the guest, someone of the tenant; you when absent"),
        "organiser": d(ANCHOR, "who organised it; you when absent"), "purpose": d(TEXT, "one line"),
        "start": d(TIME, "the meeting starts"), "end": d(TIME, "the meeting ends; the visit opens and closes around it by policy"),
        "zones": d(arr(ID, 10), "zones asked for (a Restricted zone needs a RESTRICTED badge)"),
        "escorts": d(arr(ANCHOR, 20), "staff who accompany guests that may not walk unescorted"),
        "delegation": d(obj({"name": {"type": "string", "maxLength": 80}, "organisation": {"type": "string", "maxLength": 80},
                             "contact": {"type": "string", "maxLength": 120}}, ["name"]), "optional: the group they come as"),
        "attendees": d(arr(obj({"anchor": d(ANCHOR, "a registered person"),
                                "name": d({"type": "string", "maxLength": 80}, "someone invited by name, not registered yet"),
                                "unregistered": d({"type": "boolean"}, "a companion without identity, with a label"),
                                "label": {"type": "string", "maxLength": 60}, "organisation": {"type": "string", "maxLength": 80},
                                "expected": d(TIME, "when they are expected, inside the visit window"),
                                "escort": d(ANCHOR, "who accompanies them"),
                                "kit": d(arr(obj({"class": d({"type": "string", "maxLength": 40}, "a kit class from the policy"),
                                                  "count": {"type": "integer", "minimum": 1, "maximum": 50},
                                                  "note": {"type": "string", "maxLength": 80}}, ["class"]), 20),
                                         "what they bring")}, []), 60),
                       "one per person, each arriving when and how they like; they become P1, P2, ..."),
        "vehicles": d(arr(obj({"plate": d({"type": "string", "maxLength": 20}, "kept only as a keyed digest and its last three characters"),
                               "make": {"type": "string", "maxLength": 40}, "model": {"type": "string", "maxLength": 40},
                               "colour": {"type": "string", "maxLength": 30},
                               "driver": d({"type": ["integer", "string"]}, "the driver's position (1) or id (P1), a registered attendee")},
                              ["plate"]), 10), "vehicles announced beforehand (optional)")},
        ["action", "place", "purpose", "start", "end", "attendees"]), "Register a visit (the host or the organiser)"),
    "record_entry": d(obj({"action": {"const": "record_entry"}, "visit_id": d(ID, "the visit"), "party": d(ID, "P1, P2, ..."),
                           "presented": d({"enum": ["qr", "visitor-badge", "restricted-badge", "none"]}, "what the party showed"),
                           "vehicle": d({"type": "boolean"}, "drives a vehicle in (a registered attendee only)"),
                           "vehicle_id": d(ID, "the announced vehicle they drive in (K1, ...)"),
                           "plate": d({"type": "string", "maxLength": 20}, "or the plate typed at the gate; kept only as a keyed digest"),
                           "zone": d(ID, "the zone entered, when not the site itself"),
                           "token": d({"type": "string", "maxLength": 400},
                                      "the scanned QR code; it names the visit and party, and is checked online"),
                           "checkpoint": d({"type": "string", "maxLength": 80}, "where (a gate, a reception desk)")},
                          ["action"]),
                      "Record an entry at a checkpoint (the front office): the visit and party, or the scanned code; "
                      "the entry policy decides"),
    "acknowledge_arrival": d(obj({"action": {"const": "acknowledge_arrival"}, "visit_id": d(ID, "the visit"), "party": d(ID, "P1, P2, ...")},
                                 ["action", "visit_id", "party"]), "Acknowledge a guest's arrival (the host or organiser)"),
    "confirm_guest": d(obj({"action": {"const": "confirm_guest"}, "visit_id": d(ID, "the visit"), "party": d(ID, "P1, P2, ...")}, ["action", "visit_id", "party"]),
                       "Confirm the guest is with you (the host or organiser), before the timer suspends them"),
    "add_attendee": d(obj({"action": {"const": "add_attendee"}, "visit_id": d(ID, "the visit"),
                           "attendee": d(obj({"anchor": ANCHOR, "name": {"type": "string", "maxLength": 80},
                                              "unregistered": {"type": "boolean"}, "label": {"type": "string", "maxLength": 60},
                                              "organisation": {"type": "string", "maxLength": 80}, "escort": ANCHOR}, []),
                                         "an anchor, a name, or unregistered with a label")},
                          ["action", "visit_id", "attendee"]),
                      "Add someone not on the list (the host, the organiser or the front office)"),
    "register_on_site": d(obj({"action": {"const": "register_on_site"}, "visit_id": d(ID, "the visit"),
                               "party": d(ID, "P1, P2, ..."), "anchor": d(ANCHOR, "their account after self-registering")},
                              ["action", "visit_id", "party", "anchor"]),
                          "Link an invited or unregistered attendee to their account, identity checked at the front office"),
    "issue_qr": d(obj({"action": {"const": "issue_qr"}, "visit_id": d(ID, "the visit"), "party": d(ID, "P1, P2, ...")},
                      ["action", "visit_id", "party"]),
                  "Issue a new QR code to a registered guest; the old one stops working (the guest, host or organiser)"),
    "issue_badge": d(obj({"action": {"const": "issue_badge"}, "visit_id": d(ID, "the visit"), "party": d(ID, "P1, P2, ..."),
                          "kind": d({"enum": ["visitor", "restricted"]}, "visitor (escorted) or RESTRICTED (a second person signs)"),
                          "badge": d({"type": "string", "maxLength": 40}, "the number on the badge; kept only as a keyed digest"),
                          "until": d(TIME, "when it ends; never after the visit closes")},
                         ["action", "visit_id", "party", "kind", "badge"]),
                     "Hand out a badge (the place's front office); a RESTRICTED one waits for a second key"),
    "return_badge": d(obj({"action": {"const": "return_badge"}, "badge_id": d(ID, "the badge handed back")},
                          ["action", "badge_id"]), "Record that a badge was handed back (the front office)"),
    "record_departure": d(obj({"action": {"const": "record_departure"}, "visit_id": d(ID, "the visit"), "party": d(ID, "P1, P2, ...")},
                              ["action", "visit_id", "party"]), "Record that a party left"),
    # decision 0014: edges, person keys, visit leases
    "enrol_edge": d(obj({"action": {"const": "enrol_edge"}, "edge_id": d(ID, "the edge's id"), "name": d(TEXT, "a readable name"),
                         "enrolment_key": d({"type": "string", "pattern": "^[0-9a-f]{64}$"}, "the edge agent's Ed25519 public key, hex"),
                         "officer": d(ANCHOR, "the edge's officer: never the root, the security officer or a privileged member"),
                         "officer_key": d({"type": "string", "pattern": "^[0-9a-f]{64}$"}, "the officer's ceiling-signing public key (a hardware key), hex"),
                         "profile": d({"enum": ["assured", "basic"]}, "the hardware profile claimed; attestation proves it"),
                         "custodians": d(arr(ANCHOR, 10), "the people break-glass halves may be escrowed to (at least two)"),
                         "unlock_key": d({"type": "string", "pattern": "^[A-Za-z0-9_-]{87}$"}, "the edge node's P-256 public key for phoned unlock (kc-unlock-v2), uncompressed SEC1, base64url; in its TPM where it has one"),
                         "unlock_approvers": d(arr(ANCHOR, 20), "who may read an unlock code (never the person unlocked)"),
                         "statement": d(obj({"bytes": {"type": "string", "maxLength": 16384},
                                                 "signatures": arr(obj({"key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                                                                        "key_id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
                                                                        "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}},
                                                                       ["key", "key_id", "signature"]), 3)}, ["bytes", "signatures"]),
                                           "the kc-edge-officer-v2 statement (purpose enrolment: edge, officer, officer key, the node's enrolment key, unlock key and TPM commitment), signed over the same bytes by the officer and by the edge (amendment 0014d)"),
                         "targets": d(arr(obj({"target": ID, "role": ID, "entitlement": ID,
                                               "max_session_hours": {"type": "integer", "minimum": 1, "maximum": 24}},
                                              ["target", "role", "entitlement"]), 200),
                                      "the bastion targets, each with the role it grants and the entitlement that leads to it"),
                         "reason": d(TEXT, "why; kept in the records")}, ["action", "edge_id", "enrolment_key", "officer", "officer_key", "profile",
                                                                         "statement", "targets"]),
                    "Enrol an edge (the root; waits for the security officer's key)"),
    "enrol_person_key": d(obj({"action": {"const": "enrol_person_key"},
                               "public_key": d({"type": "string", "maxLength": 64}, "the X25519 public key derived from your passkey through PRF, base64url"),
                               "ssh_key": d({"type": "string", "maxLength": 900}, "the ssh-ed25519 public key your hardware key holds"),
                               "credential_id": d({"type": "string", "maxLength": 400}, "the WebAuthn credential id the key came from"),
                               "user_verification": d({"const": True}, "the authenticator verified you (PIN or biometric)"),
                               "attestation": d({"type": "string", "maxLength": 40}, "the attestation format the authenticator gave, if any")},
                              ["action", "public_key", "user_verification"]),
                          "Register your hardware key (yourself; waits for a second key)"),
    "grant_visit_lease": d(obj({"action": {"const": "grant_visit_lease"}, "edge": d(ID, "the assured edge"),
                                "person": d(ANCHOR, "who visits"),
                                "ssh_key": d({"type": "string", "maxLength": 900}, "their registered hardware SSH key"),
                                "targets": d(arr(ID, 20), "targets on that edge"), "from": d(TIME, "when the window opens (default now)"),
                                "hours": d({"type": "integer", "minimum": 1, "maximum": 720}, "the window, at most what edge.rego and the ceiling allow"),
                                "reason": d(TEXT, "why; kept in the records")}, ["action", "edge", "person", "ssh_key", "targets", "hours"]),
                           "Grant a visit lease on an assured edge (waits for a second key)"),
    "rotate_edge": d(obj({"action": {"const": "rotate_edge"}, "edge_id": d(ID, "the edge"),
                          "enrolment_key": d({"type": "string", "pattern": "^[0-9a-f]{64}$"}, "the edge's new (or same) enrolment key"),
                          "officer": d(ANCHOR, "the edge's (new or same) officer"),
                          "officer_key": d({"type": "string", "pattern": "^[0-9a-f]{64}$"}, "the officer's (new or same) key"),
                          "unlock_key": d({"type": "string", "pattern": "^[A-Za-z0-9_-]{87}$"}, "the edge node's P-256 public key for phoned unlock (kc-unlock-v2), uncompressed SEC1, base64url; in its TPM where it has one"),
                          "statement": d(obj({"bytes": {"type": "string", "maxLength": 16384},
                                                 "signatures": arr(obj({"key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                                                                        "key_id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
                                                                        "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}},
                                                                       ["key", "key_id", "signature"]), 3)}, ["bytes", "signatures"]),
                                            "the kc-edge-officer-v2 statement with purpose rotation, signed by the (new) officer and the edge's (new) enrolment key"),
                          "reason": d(TEXT, "why; kept in the records")},
                         ["action", "edge_id", "enrolment_key", "officer", "officer_key", "statement"]),
                     "Rotate an edge's enrolment key or officer (waits for the security officer's key)"),
    "end_edge_record": d(obj({"action": {"const": "end_edge_record"}, "id": d(ID, "an edge, a person key or a visit lease"),
                              "reason": d(TEXT, "why; kept in the records")}, ["action", "id", "reason"]),
                         "End an edge, a person key or a visit lease"),
}
for k, v in REQ.items():
    S["Request_" + k] = v
S["ChangeRequest"] = {"oneOf": [ref("Request_" + k) for k in REQ]}

ERR = {code: {"description": d, "content": {"application/json": {"schema": ref("Error")}}}
       for code, d in (("400", "invalid input"), ("401", "not signed in"), ("403", "not allowed, or the CSRF header is missing"),
                       ("404", "not found"), ("413", "body too large"), ("415", "not JSON"), ("422", "refused"),
                       ("429", "too many requests from one person"), ("503", "busy"))}


def op(summary, schema=None, params=(), body=None, codes=("401", "403", "429"), tag="read"):
    codes = tuple(sorted({"400", *codes}))         # any input may be malformed: a 400 is always possible (fuzzing)
    o = {"summary": summary, "tags": [tag], "security": [{"bearer": []}, {"session": []}],
         "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": schema}}},
                       **{c: ERR[c] for c in codes}}}
    if params:
        o["parameters"] = [{"name": p, "in": "path", "required": True, "schema": ANCHOR if p == "anchor" else ID} for p in params]
    if body:
        o["requestBody"] = {"required": True, "content": {"application/json": {"schema": body}}}
    return o


W = ("400", "401", "403", "404", "413", "415", "422", "429", "503")
doc = {
    "openapi": "3.1.0",
    "info": {"title": "KeyClerk API", "version": "1",
             "description": "Everything a KeyClerk front end can see and do. Reads are views over the records, filtered "
                            "by who asks; writes are change requests that the engine applies, holds for a second key, or "
                            "refuses with reasons. A browser session (cookie) sends the CSRF token from /me in the "
                            "X-KeyClerk-CSRF header on every POST; a front end with its own broker client sends a bearer "
                            "token from an allowed client. Errors share one shape."},
    "servers": [{"url": "/api/v1"}],
    "components": {"schemas": S, "securitySchemes": {
        "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT (RS256, from the broker; azp an allowed client)"},
        "session": {"type": "apiKey", "in": "cookie", "name": "keyclerk_session"},
        "edge": {"type": "apiKey", "in": "header", "name": "KeyClerk-Edge",
                 "description": "edge;unix seconds;nonce;Ed25519 signature hex over kc-edge-request-v1, METHOD, path with query, "
                                "seconds, nonce and the body's sha256, newline-separated (decision 0014; keyclerk/edge.py)"}}},
    "paths": {
        "/me/keys": {"get": op("My registered person keys (decision 0014)", arr(ref("PersonKey")))},
        "/relay": {"get": op("Ciphertexts waiting for me: what they are for and when they expire, never their content",
                              arr(ref("RelayItem")))},
        "/relay/{relay_id}/take": {"post": op("Take a ciphertext once, within 10 minutes of a fresh sign-in; your browser "
                                                 "decrypts it with the key your passkey derives", ref("RelayTaken"), ["relay_id"],
                                                 codes=("401", "403", "404", "429"), tag="change")},
        "/edges": {"get": op("Edges and their state (a viewer, the root, the security officer, or an edge's officer)",
                              arr({"type": "object"}))},
        "/edges/{edge_id}/ceiling": {"post": op("Set an edge's ceiling: the officer's signed data (decision 0014 point 4)",
                                                   {"type": "object"}, ["edge_id"], body=ref("SignedCeiling"), codes=W, tag="change")},
        "/relay/{relay_id}/confirm": {"post": op("Confirm you opened it: a credential is deleted, an escrow half recorded",
                                                 {"type": "object"}, ["relay_id"], codes=("401", "403", "404", "429"), tag="change")},
        "/edge/escrow/{item_id}": {"get": {**op("Whether both custodians opened their halves; forget the value only then",
                                                {"type": "object"}, ["item_id"]), "security": [{"edge": []}], "tags": ["edge"]}},
        "/edge/lease/{lease_id}/email": {"get": {**op("The verified address of a live lease's person, sealed for this "
                                                      "request (edge protocol 1.3); the edge keeps it nowhere",
                                                      {"type": "object"}, ["lease_id"], codes=("401", "404", "429")),
                                                 "security": [{"edge": []}], "tags": ["edge"]}},
        "/edges/{edge_id}/unlock": {"post": op("Read a phoned-unlock code (an unlock approver of the edge, never the person)",
                                               {"type": "object"}, ["edge_id"], body={"type": "object"}, codes=W, tag="change")},
        "/edges/{edge_id}/incidents/{incident_id}/close": {"post": op("Close an edge incident (its officer or the security officer)",
                                                                      {"type": "object"}, ["edge_id", "incident_id"], body={"type": "object"},
                                                                      codes=W, tag="change")},
        "/me/visit-leases": {"get": op("My visit leases on edges", arr({"type": "object"}))},
        "/me/visit-leases/{lease_id}/carried": {"post": op("A carried visit lease for the edge (after a fresh sign-in)",
                                                           {"type": "object"}, ["lease_id"], codes=("401", "403", "404", "422", "429"),
                                                           tag="change")},
        "/edge-key": {"get": {**op("The bundle key's public half, which an edge pins at enrolment (public)", {"type": "object"}),
                               "security": []}},
        "/edge/bundle": {"get": {**op("The signed bundle for the calling edge (decision 0014 point 3)", {"type": "object"}),
                                  "security": [{"edge": []}], "tags": ["edge"]}},
        "/edge/module/{sha256}": {"get": {**op("A policy module the edge's bundle names by hash: fetched once per change "
                                                "and kept by hash; the agent checks the bytes against the hash",
                                                {"type": "object"}, ["sha256"]), "security": [{"edge": []}], "tags": ["edge"]}},
        "/edge/report": {"post": {**op("What the edge applied, its attestation and drift", {"type": "object"}, body={"type": "object"}, codes=W),
                                   "security": [{"edge": []}], "tags": ["edge"]}},
        "/edge/attest/challenge": {"get": {**op("A credential activation challenge for the edge's TPM (decision 0016)",
                                                {"type": "object"}, codes=W), "security": [{"edge": []}], "tags": ["edge"]}},
        "/edge/attest/activate": {"post": {**op("The recovered challenge: the attestation key is in the pinned TPM",
                                                 {"type": "object"}, body={"type": "object"}, codes=W),
                                            "security": [{"edge": []}], "tags": ["edge"]}},
        "/edge/relay": {"post": {**op("A ciphertext for one person key, relayed once", {"type": "object"}, body={"type": "object"}, codes=W),
                                  "security": [{"edge": []}], "tags": ["edge"]}},
        "/edge/escrow": {"post": {**op("A break-glass value as two custodian ciphertexts; a signed acknowledgement",
                                         {"type": "object"}, body={"type": "object"}, codes=W), "security": [{"edge": []}], "tags": ["edge"]}},
        "/edge/incident": {"post": {**op("An incident the edge saw (break-glass used, drift, evidence floor)", {"type": "object"},
                                           body={"type": "object"}, codes=W), "security": [{"edge": []}], "tags": ["edge"]}},
        "/edge/evidence": {"get": {**op("The evidence chain's head as the desk holds it (after a lost acknowledgement)",
                                        {"type": "object"}), "security": [{"edge": []}], "tags": ["edge"]},
                           "post": {**op("Recording hashes as a chain; a signed acknowledgement up to a sequence", {"type": "object"},
                                           body={"type": "object"}, codes=W), "security": [{"edge": []}], "tags": ["edge"]}},
        "/me": {"get": op("Who I am, what I hold and manage, the CSRF token for a browser session", ref("Me"))},
        "/people": {"get": op("Everyone the records know", arr(ref("Person")))},
        "/people/{anchor}": {"get": op("One person's access and why (yourself; a viewer or the root: anyone)",
                                       ref("PersonAccess"), ["anchor"], codes=("401", "403", "404", "429"))},
        "/people/{anchor}/graph": {"get": {**op("One person's graph at a moment: accounts by identity source, groups, "
                                                "delegations, places and the people around them, as far as you may see "
                                                "(view policy); marks are the changes before and after the moment",
                                                ref("PersonGraph"), ["anchor"], codes=("400", "401", "403", "404", "422", "429")),
                                            "parameters": [{"name": "anchor", "in": "path", "required": True,
                                                            "schema": ANCHOR},
                                                           {"name": "at", "in": "query", "required": False,
                                                            "description": "the moment (RFC 3339); now when absent",
                                                            "schema": {"type": "string", "format": "date-time"}}]}},
        "/groups": {"get": op("The group tree with my powers on each group", arr(ref("Group")))},
        "/groups/{group_id}": {"get": op("A group: members and why, nesting, managers and their chains",
                                         ref("GroupDetail"), ["group_id"], codes=("401", "403", "404", "429"))},
        "/delegations": {"get": op("Every delegation, its chain and state", arr(ref("Delegation")))},
        "/visits": {"get": op("Visits you host, organise, receive at your place's front office, or come on", arr(ref("VisitSummary")))},
        "/visits/{visit_id}": {"get": {**op("One visit at a moment: parties, vehicle, kit, the timeline, what the gate says, "
                                            "what you may record", ref("VisitDetail"), codes=("400", "401", "403", "422", "429")),
                                       "parameters": [{"name": "visit_id", "in": "path", "required": True, "schema": ID},
                                                      {"name": "at", "in": "query", "required": False,
                                                       "description": "the moment (RFC 3339); now when absent",
                                                       "schema": {"type": "string", "format": "date-time"}}]}},
        "/visits/{visit_id}/qr/{party}": {"get": {**op("A guest's current QR code: the code, the link it opens and the image "
                                                       "(the guest, the host or the organiser)",
                                                       obj({"visit_id": ID, "party": ID, "serial": {"type": "integer"},
                                                            "until": TIME, "token": TEXT, "url": TEXT, "image": TEXT}),
                                                       codes=("401", "403", "422", "429")),
                                                  "parameters": [{"name": "visit_id", "in": "path", "required": True, "schema": ID},
                                                                 {"name": "party", "in": "path", "required": True, "schema": ID}]}},
        "/scan/{token}": {"get": {"summary": "The phone scan (no sign-in): may this guest walk unescorted, and until when; "
                                             "checked online now; nothing else is told",
                                  "tags": ["visit"], "security": [],
                                  "parameters": [{"name": "token", "in": "path", "required": True,
                                                  "schema": {"type": "string", "maxLength": 400}}],
                                  "responses": {"200": {"description": "the answer", "content": {"application/json": {"schema":
                                                obj({"unescorted": {"type": "boolean"}, "checked": {"enum": ["online"]},
                                                     "at": TIME, "until": NULLS(TIME)})}}},
                                                "400": ERR["400"], "429": ERR["429"]}}},
        "/qr-key": {"get": {"summary": "The public key visit codes are signed with, for checkpoints that check offline "
                                       "(signature and expiry only; no sign-in)",
                            "tags": ["visit"], "security": [],
                            "responses": {"200": {"description": "the key", "content": {"application/json": {"schema":
                                          obj({"kid": TEXT, "alg": TEXT, "key": TEXT, "format": TEXT})}}}}}},
        "/delegations/tree": {"get": {**op("The delegation tree at a moment: what was handed on, to whom, how deep, "
                                           "until when, as far as you may see (tree policy)", ref("DelegationTree"),
                                           codes=("400", "401", "403", "422", "429")),
                                      "parameters": [{"name": "at", "in": "query", "required": False,
                                                      "description": "the moment (RFC 3339); now when absent",
                                                      "schema": {"type": "string", "format": "date-time"}}]}},
        "/changes": {"get": op("Changes waiting for a key, and the change log", ref("Changes")),
                     "post": op("Request a change: applied, pending (waits for a key) or refused, with reasons",
                                ref("ChangeResult"), body=ref("ChangeRequest"), codes=W, tag="change")},
        "/changes/preview": {"post": op("What a change request would answer, without doing anything: nothing is "
                                        "applied, held or logged", ref("Preview"), body=ref("ChangeRequest"), codes=W, tag="change")},
        "/changes/{change_id}/statement": {"get": op("What my approval of a waiting change must sign: the nonce for a fresh "
                                                     "sign-in at the broker (decision 0006)", ref("Statement"), ["change_id"],
                                                     codes=("401", "403", "422", "429"), tag="change")},
        "/changes/{change_id}/approval-sign-in": {"post": op("Start approving in a browser session on this desk: the answer "
                                                             "names the broker's sign-in to go to (the sign-in signs the change)",
                                                             ref("SignIn"), ["change_id"], codes=W, tag="change")},
        "/changes/{change_id}/phone-link": {"get": op("A short-lived link (and its QR image) to approve this change on "
                                                      "another device, such as a phone: the same signed approval",
                                                      ref("PhoneLink"), ["change_id"], codes=("401", "403", "422", "429"),
                                                      tag="change")},
        "/changes/{change_id}/approve": {"post": op("Add my key to a waiting change; where approvals need proofs, the body "
                                                    "carries the broker's ID token from a fresh sign-in with the statement's "
                                                    "nonce", ref("ChangeResult"), ["change_id"], body=ref("ApproveRequest"),
                                                    codes=W, tag="change")},
        "/changes/{change_id}/withdraw": {"post": op("Withdraw a waiting change (who proposed it, or the root)",
                                                     ref("ChangeResult"), ["change_id"], codes=W, tag="change")},
        "/broker": {"get": op("What the reconciler did with the records: its last runs", ref("Broker"))},
        "/openapi.json": {"get": {"summary": "This contract (no sign-in needed)", "tags": ["about"], "security": [],
                                  "responses": {"200": {"description": "the OpenAPI document",
                                                        "content": {"application/json": {"schema": {"type": "object"}}}}}}},
    },
}

def render() -> str:
    return json.dumps(doc, indent=1) + "\n"


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        same = OUT.read_text(encoding="utf-8") == render()
        print("contract up to date" if same else "contract differs: run python tools/gen_api_contract.py")
        sys.exit(0 if same else 1)
    OUT.write_text(render(), encoding="utf-8", newline="\n")
    print("paths", len(doc["paths"]), "schemas", len(S))
