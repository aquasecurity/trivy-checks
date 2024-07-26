package builtin.nifcloud.computing.nifcloud0004_test

import rego.v1

import data.builtin.nifcloud.computing.nifcloud0004 as check
import data.lib.test

test_allow_instance_with_sg if {
	inp := {"nifcloud": {"computing": {"instances": [{"securitygroup": {"value": "some-sg"}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_instance_without_sg if {
	inp := {"nifcloud": {"computing": {"instances": [{"securitygroup": {"value": ""}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
