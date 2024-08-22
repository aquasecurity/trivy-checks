package builtin.digitalocean.spaces.digitalocean0009_test

import rego.v1

import data.builtin.digitalocean.spaces.digitalocean0009 as check
import data.lib.test

test_allow_force_destroy_disabled if {
	inp := {"digitalocean": {"spaces": {"buckets": [{"forcedestroy": {"value": false}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_force_destroy_enabled if {
	inp := {"digitalocean": {"spaces": {"buckets": [{"forcedestroy": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
