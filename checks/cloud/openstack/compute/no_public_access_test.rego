package builtin.openstack.compute.openstack0002_test

import rego.v1

import data.builtin.openstack.compute.openstack0002 as check
import data.lib.test

test_deny_rule_missing_destination_address if {
	inp := build_input({
		"enabled": {"value": true},
		"destination": {"value": ""},
		"source": {"value": "10.10.10.1"},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_rule_missing_source_address if {
	inp := build_input({
		"enabled": {"value": true},
		"destination": {"value": "10.10.10.1"},
		"source": {"value": ""},
	})
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_rule if {
	inp := build_input({
		"enabled": {"value": true},
		"destination": {"value": "10.10.10.1"},
		"source": {"value": "10.10.10.1"},
	})

	res := check.deny with input as inp
	res == set()
}

test_allow_disabled_rule if {
	inp := build_input({
		"enabled": {"value": false},
		"destination": {"value": ""},
		"source": {"value": ""},
	})

	res := check.deny with input as inp
	res == set()
}

build_input(rule) := {"openstack": {"compute": {"firewall": {"allowrules": [rule]}}}}
