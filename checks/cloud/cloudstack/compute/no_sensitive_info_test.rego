package builtin.cloudstack.compute.cloudstack0001_test

import rego.v1

import data.builtin.cloudstack.compute.cloudstack0001 as check
import data.lib.test

test_deny_compute_instance_with_sensitive_data if {
	inp := {"cloudstack": {"compute": {"instances": [{"userdata": {"value": " export DATABASE_PASSWORD=\"SomeSortOfPassword\""}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_compute_instance_without_sensitive_data if {
	inp := {"cloudstack": {"compute": {"instances": [{"userdata": {"value": ` export GREETING="Hello there"`}}]}}}

	res := check.deny with input as inp
	res == set()
}
