package builtin.azure.keyvault.azure0016_test

import rego.v1

import data.builtin.azure.keyvault.azure0016 as check
import data.lib.test

test_deny_purge_protection_disabled if {
	inp := {"azure": {"keyvault": {"vaults": [{}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_purge_protection_enabled_but_soft_delete_retention_days_less_than_7 if {
	inp := {"azure": {"keyvault": {"vaults": [{"enablepurgeprotection": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_purge_protection_enabled_but_soft_delete_retention_days_greater_than_90 if {
	inp := {"azure": {"keyvault": {"vaults": [{
		"enablepurgeprotection": {"value": true},
		"softdeleteretentiondays": {"value": 91},
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_purge_protection_enabled_and_soft_delete_retention_days_between_7_and_90 if {
	inp := {"azure": {"keyvault": {"vaults": [{
		"enablepurgeprotection": {"value": true},
		"softdeleteretentiondays": {"value": 30},
	}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
