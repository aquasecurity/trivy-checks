package builtin.azure.storage.azure0061_test

import rego.v1

import data.builtin.azure.storage.azure0061 as check
import data.lib.test

test_deny_infrastructure_encryption_disabled if {
	inp := {"azure": {"storage": {"accounts": [{"infrastructureencryptionenabled": {"value": false}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_infrastructure_encryption_not_configured if {
	inp := {"azure": {"storage": {"accounts": [{}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_infrastructure_encryption_enabled if {
	inp := {"azure": {"storage": {"accounts": [{"infrastructureencryptionenabled": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}
