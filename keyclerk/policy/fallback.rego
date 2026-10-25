# The fallback ladder: when a checkpoint's normal requirement (a second person, an
# escort) cannot be met now, the first step of its ladder that the label, the risk band, the situation level and the
# urgency allow, and whose own pool is available. Data: data.keyclerk.availability (the
# availability section of the configuration). keyclerk.pools.fallback is the reference; tests/test_pools.py holds both to the same cases.
package keyclerk.fallback

import rego.v1

rd := data.keyclerk.availability

levels := ["normal", "elevated", "high", "severe"]

level_index(l) := i if levels[i] == l

remote_steps := {"remote_confirm", "supervised"}

# A remote step is allowed only when it is positively open: the label names the last level it is open at and the
# current level is known and not above it. Missing data closes it (never fail open).
allowed contains s if {
	some s in rd.allowed_steps[input.label]
	not s in remote_steps
}

allowed contains s if {
	some s in rd.allowed_steps[input.label]
	s in remote_steps
	remote_open
}

remote_open if level_index(input.level) <= level_index(rd.remote_steps_until_level[input.label])

usable(s) if {
	s == "remote_confirm"
	input.available.site_office
}

usable(s) if {
	s == "supervised"
	input.available.remote_watch
	input.urgent
}

usable(s) if {
	s == "supervised"
	input.available.remote_watch
	input.label == "Internal"
}

usable(s) if s in {"deferred", "never"}

candidates := [s | some s in input.ladder; s in allowed; usable(s)]

input_ok if {
	input.label in {"Internal", "Sensitive", "Restricted"}
	input.band in {"green", "amber", "red", "black"}
	input.level in {"normal", "elevated", "high", "severe"}
	is_array(input.ladder)
	count(input.ladder) <= 10
	every s in input.ladder {
		s in {"remote_confirm", "supervised", "deferred", "never"}
	}
	is_boolean(input.urgent)
}

default step := "never"

step := "deferred" if {
	input_ok
	count(candidates) == 0
	not input.band in {"red", "black"}
	not never_when_empty
}

never_when_empty if {
	input.label == "Restricted"
	not "deferred" in input.ladder
}


step := candidates[0] if {
	input_ok
	not input.band in {"red", "black"}
	count(candidates) > 0
}

step := "never" if {
	not input.band in {"red", "black"}
	count(candidates) == 0
	input.label == "Restricted"
	not "deferred" in input.ladder
}

obligations := rd.steps[step].obligations
