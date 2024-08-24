package builtin.openstack.networking.openstack0005_test

import rego.v1

import data.builtin.openstack.networking.openstack0005 as check
import data.lib.test

test_allow_sg_with_description if {
	inp := {"openstack": {"networking": {"securitygroups": [{"description": {"value": "test"}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_sg_without_description if {
	inp := {"openstack": {"networking": {"securitygroups": [{"description": {"value": ""}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
