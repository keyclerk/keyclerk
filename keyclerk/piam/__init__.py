# SPDX-License-Identifier: EUPL-1.2
"""Physical access for the access lease.

Two ways to the door, one shared core:
- pacs: where a site has a physical access control system (PACS head-end with field controllers), the lease is pushed
  down to the head-end as a cardholder with a credential and an access level per site or area, with its activation and
  expiry dates stored in the PACS. The field controllers keep the cardholder database and decide offline, so the lease
  end holds at the door when the IT link is cut. Events (granted, denied, entry, exit) come back up.
- osdp: where a small site (an access enclave) has no PACS, this package is the controller: it speaks OSDP to the
  readers (libosdp control panel), keeps the badge allowlist with lease ends from the signed bundle, decides on each
  card read, drives the reader's LED and buzzer and an output for the strike where the device has one.

IT/OT conduit (IEC 62443 zones and conduits shape): one connector per site, from the IT zone to the PACS zone; it
pushes cardholders down and takes events up; nothing in the OT zone opens a connection into the IT zone except the
event feed, and the connector holds no other OT access. Life safety (egress, fire release) stays with the PACS and
the door hardware, never with this code.

core holds what both share: badge records from lease data (the badge id kept only as a keyed hash), the decision on a
card read, the roll call per site and OCSF-shaped events.
"""
