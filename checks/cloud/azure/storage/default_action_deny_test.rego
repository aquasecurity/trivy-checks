package builtin.azure.storage.azure0012_test

import rego.v1

import data.builtin.azure.storage.azure0012 as check
import data.lib.test

test_deny_rule_allow_acces_by_default if {
	inp := {"azure": {"storage": {"accounts": [{"networkrules": [{"allowbydefault": {"value": true}}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_rule_deny_acces_by_default if {
	inp := {"azure": {"storage": {"accounts": [{"networkrules": [{"allowbydefault": {"value": false}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
