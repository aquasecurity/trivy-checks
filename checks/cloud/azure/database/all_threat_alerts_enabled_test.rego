package builtin.azure.database.azure0028_test

import rego.v1

import data.builtin.azure.database.azure0028 as check
import data.lib.test

test_deny_server_alerts_for_sql_injection_disabled if {
	inp := {"azure": {"database": {"mssqlservers": [{"securityalertpolicies": [{"disabledalerts": [{"value": "Sql_Injection"}]}]}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_server_alerts_for_sql_injection_enabled if {
	inp := {"azure": {"database": {"mssqlservers": [{"securityalertpolicies": [{"disabledalerts": []}]}]}}}
	res := check.deny with input as inp
	count(res) == 0
}
