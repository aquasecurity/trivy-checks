package builtin.azure.database.azure0025_test

import rego.v1

import data.builtin.azure.database.azure0025 as check
import data.lib.test

test_deny_retention_period_less_than_90_days if {
	inp := {"azure": {"database": {"mssqlservers": [{"extendedauditingpolicies": [{"retentionindays": {"value": 30}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_default_retention_period if {
	inp := {"azure": {"database": {"mssqlservers": [{"extendedauditingpolicies": [{"retentionindays": {"value": 0}}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_retention_period_greater_than_90_days if {
	inp := {"azure": {"database": {"mssqlservers": [{"extendedauditingpolicies": [{"retentionindays": {"value": 100}}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
