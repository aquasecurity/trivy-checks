package builtin.azure.keyvault.azure0017_test

import rego.v1

import data.builtin.azure.keyvault.azure0017 as check
import data.lib.datetime
import data.lib.test

test_deny_expiration_date_not_specified if {
	inp := {"azure": {"keyvault": {"vaults": [{"secrets": [{}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_expiration_date_is_zero if {
	inp := {"azure": {"keyvault": {"vaults": [{"secrets": [{"expirydate": {"value": datetime.zero_time_string}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_expiration_date_is_not_zero if {
	inp := {"azure": {"keyvault": {"vaults": [{"secrets": [{"expirydate": {"value": "2024-01-01T00:00:00Z"}}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
