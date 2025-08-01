package builtin.google.dns.google0013_test

import rego.v1

import data.builtin.google.dns.google0013 as check

test_deny_dns_sec_disabled if {
	inp := build_input({
		"visibility": {"value": "public"},
		"dnssec": {"enabled": {"value": false}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_dns_sec_enabled if {
	inp := build_input({
		"visibility": {"value": "public"},
		"dnssec": {"enabled": {"value": true}},
	})

	res := check.deny with input as inp
	res == set()
}

test_allow_dns_sec_disabled_for_private_zone if {
	inp := build_input({
		"visibility": {"value": "private"},
		"dnssec": {"enabled": {"value": false}},
	})

	res := check.deny with input as inp
	res == set()
}

build_input(zone) := {"google": {"dns": {"managedzones": [zone]}}}
