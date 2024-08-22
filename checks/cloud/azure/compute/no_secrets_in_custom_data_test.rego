package builtin.azure.compute.azure0037_test

import rego.v1

import data.builtin.azure.compute.azure0037 as check
import data.lib.test

test_deny_secrets_in_custom_data if {
	inp := {"azure": {"compute": {"linuxvirtualmachines": [{"virtualmachine": {"customdata": {"value": `export DATABASE_PASSWORD=\"SomeSortOfPassword\"`}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_no_secrets_in_custom_data if {
	inp := {"azure": {"compute": {"linuxvirtualmachines": [{"virtualmachine": {"customdata": {"value": `export GREETING="Hello there"`}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
