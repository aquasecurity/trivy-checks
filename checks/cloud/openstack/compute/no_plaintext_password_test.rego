package builtin.openstack.compute.openstack0001_test

import rego.v1

import data.builtin.openstack.compute.openstack0001 as check
import data.lib.test

test_allow_no_plaintext_password if {
	inp := {"openstack": {"compute": {"instances": [{"adminpassword": {"value": ""}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_with_plaintext_password if {
	inp := {"openstack": {"compute": {"instances": [{"adminpassword": {"value": "password"}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
