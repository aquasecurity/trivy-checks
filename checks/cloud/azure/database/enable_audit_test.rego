package builtin.azure.database.azure0027_test

import rego.v1

import data.builtin.azure.database.azure0027 as check
import data.lib.test

test_deny_extended_audit_policy_not_configured if {
	inp := {"azure": {"database": {"mssqlservers": [{"extendedauditingpolicies": []}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_extended_audit_policy_not_specified if {
	inp := {"azure": {"database": {"mssqlservers": [{}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_extended_audit_policy_configured if {
	inp := {"azure": {"database": {"mssqlservers": [{"extendedauditingpolicies": [{"retentionindays": {"value": 6}}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
