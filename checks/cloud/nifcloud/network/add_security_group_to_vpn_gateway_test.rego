package builtin.nifcloud.network.nifcloud0018_test

import rego.v1

import data.builtin.nifcloud.network.nifcloud0018 as check
import data.lib.test

test_allow_gateway_with_sg if {
	inp := {"nifcloud": {"network": {"vpngateways": [{"securitygroup": {"value": "some-group"}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_gateway_without_sg if {
	inp := {"nifcloud": {"network": {"vpngateways": [{"securitygroup": {"value": ""}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}
