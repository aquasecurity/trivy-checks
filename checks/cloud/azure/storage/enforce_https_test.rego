package builtin.azure.storage.azure0008_test

import rego.v1

import data.builtin.azure.storage.azure0008 as check
import data.lib.test

test_deny_https_enforcement_disabled if {
	inp := {"azure": {"storage": {"accounts": [{"enforcehttps": {"value": false}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_https_enforcement_enabled if {
	inp := {"azure": {"storage": {"accounts": [{"enforcehttps": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}
