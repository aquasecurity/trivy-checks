package builtin.azure.storage.azure0056_test

import rego.v1

import data.builtin.azure.storage.azure0056 as check
import data.lib.test

test_deny_soft_delete_disabled if {
	inp := {"azure": {"storage": {"accounts": [{"blobproperties": {"deleteretentionpolicy": {"days": {"value": 0}}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_soft_delete_not_configured if {
	inp := {"azure": {"storage": {"accounts": [{}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_soft_delete_enabled if {
	inp := {"azure": {"storage": {"accounts": [{"blobproperties": {"deleteretentionpolicy": {"days": {"value": 7}}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_soft_delete_enabled_long_retention if {
	inp := {"azure": {"storage": {"accounts": [{"blobproperties": {"deleteretentionpolicy": {"days": {"value": 365}}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
