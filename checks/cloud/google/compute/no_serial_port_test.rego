package builtin.google.compute.google0032_test

import rego.v1

import data.builtin.google.compute.google0032 as check
import data.lib.test

test_deny_instance_serial_port_enabled if {
	inp := {"google": {"compute": {"instances": [{"enableserialport": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_instance_serial_port_disabled if {
	inp := {"google": {"compute": {"instances": [{"enableserialport": {"value": false}}]}}}

	res := check.deny with input as inp
	res == set()
}
