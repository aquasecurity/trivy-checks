package builtin.digitalocean.compute.digitalocean0003_test

import rego.v1

import data.builtin.digitalocean.compute.digitalocean0003 as check
import data.lib.test

test_deny_multiple_public_destinations if {
	inp := {"digitalocean": {"compute": {"firewalls": [{"outboundrules": [{"destinationaddresses": [
		{"value": "0.0.0.0/0"},
		{"value": "::/0"},
	]}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_private_destination if {
	inp := {"digitalocean": {"compute": {"firewalls": [{"outboundrules": [{"destinationaddresses": [{"value": "192.168.1.0/24"}]}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
