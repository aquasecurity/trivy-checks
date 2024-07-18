package builtin.azure.database.azure0023_test

import rego.v1

import data.builtin.azure.database.azure0023 as check
import data.lib.test

test_deny_alert_account_admins_disabled if {
	inp := {"azure": {"database": {"mssqlservers": [{"securityalertpolicies": [{"emailaccountadmins": {"value": false}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_alert_account_admins_enabled if {
	inp := {"azure": {"database": {"mssqlservers": [{"securityalertpolicies": [{"emailaccountadmins": {"value": true}}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
