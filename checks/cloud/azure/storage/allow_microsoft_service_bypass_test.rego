package builtin.azure.storage.azure0010_test

import rego.v1

import data.builtin.azure.storage.azure0010 as check
import data.lib.test

test_deny_rule_does_not_allow_bypass_access if {
	inp := {"azure": {"storage": {"accounts": [{
		"name": "test",
		"networkrules": [{"bypass": []}],
	}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_rule_allow_bypass_access if {
	inp := {"azure": {"storage": {"accounts": [{"networkrules": [{"bypass": [{"value": "AzureServices"}]}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
