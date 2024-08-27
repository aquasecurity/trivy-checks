package builtin.digitalocean.compute.digitalocean0001_test

import rego.v1

import data.builtin.digitalocean.compute.digitalocean0001 as check
import data.lib.test

test_deny_multiple_public_sources if {
	inp := {"digitalocean": {"compute": {"firewalls": [{"inboundrules": [{"sourceaddresses": [
		{"value": "0.0.0.0/0"},
		{"value": "::/0"},
	]}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_private_source if {
	inp := {"digitalocean": {"compute": {"firewalls": [{"inboundrules": [{"sourceaddresses": [{"value": "192.168.1.0/24"}]}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
