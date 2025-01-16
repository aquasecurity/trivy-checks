package builtin.openstack.networking.openstack0003_test

import rego.v1

import data.builtin.openstack.networking.openstack0003 as check

test_deny_public_ingress if {
	inp := {"openstack": {"networking": {"securitygroups": [{"rules": [{
		"isingress": {"value": true},
		"cidr": {"value": "*"},
	}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_non_public_ingress if {
	inp := {"openstack": {"networking": {"securitygroups": [{"rules": [{
		"isingress": {"value": true},
		"cidr": {"value": "10.0.0.0/16"},
	}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
