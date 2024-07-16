package builtin.google.dns.google0012_test

import rego.v1

import data.builtin.google.dns.google0012 as check
import data.lib.test

test_deny_rsa_sha1 if {
	inp := build_input({"algorithm": {"value": "rsasha1"}})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_rsa_sha512 if {
	inp := build_input({"algorithm": {"value": "rsasha512"}})

	check.deny with input as inp == set()
}

build_input(key_spec) := {"google": {"dns": {"managedzones": [{"dnssec": {"defaultkeyspecs": [key_spec]}}]}}}
