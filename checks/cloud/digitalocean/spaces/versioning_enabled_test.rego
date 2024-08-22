package builtin.digitalocean.spaces.digitalocean0007_test

import rego.v1

import data.builtin.digitalocean.spaces.digitalocean0007 as check
import data.lib.test

test_allow_versioning_enabled if {
	inp := {"digitalocean": {"spaces": {"buckets": [{"versioning": {"enabled": {"value": true}}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_versioning_disabled if {
	inp := {"digitalocean": {"spaces": {"buckets": [{"versioning": {"enabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
