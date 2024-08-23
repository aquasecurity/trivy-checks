package builtin.azure.database.azure0018_test

import rego.v1

import data.builtin.azure.database.azure0018 as check
import data.lib.test

test_deny_policy_has_no_emails_for_threat_alerts if {
	inp := {"azure": {"database": {"mssqlservers": [{"securityalertpolicies": [{}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_policy_has_emails_for_threat_alerts if {
	inp := {"azure": {"database": {"mssqlservers": [{"securityalertpolicies": [{"emailaddresses": [{"value": "sample@email.com"}]}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
