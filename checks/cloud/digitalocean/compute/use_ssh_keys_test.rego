package builtin.digitalocean.compute.digitalocean0004_test

import rego.v1

import data.builtin.digitalocean.compute.digitalocean0004 as check
import data.lib.test

test_deny_missing_ssh_keys if {
	inp := {"digitalocean": {"compute": {"droplets": [{"sshkeys": []}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_ssh_keys_present if {
	inp := {"digitalocean": {"compute": {"droplets": [{"sshkeys": [{"value": "foo"}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
