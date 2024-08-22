package builtin.nifcloud.network.nifcloud0016_test

import rego.v1

import data.builtin.nifcloud.network.nifcloud0016 as check
import data.lib.test

test_allow_router_with_sg if {
	inp := {"nifcloud": {"network": {"routers": [{"securitygroup": {"value": "some-group"}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_router_without_sg if {
	inp := {"nifcloud": {"network": {"routers": [{"securitygroup": {"value": ""}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
