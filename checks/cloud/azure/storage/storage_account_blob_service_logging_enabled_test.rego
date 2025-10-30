package builtin.azure.storage.azure0058_test

import rego.v1

import data.builtin.azure.storage.azure0058 as check
import data.lib.test

test_deny_blob_logging_with_containers if {
	inp := {"azure": {"storage": {"accounts": [{"containers": [{"publicaccess": {"value": "private"}}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_no_containers if {
	inp := {"azure": {"storage": {"accounts": [{"containers": []}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_account_without_containers if {
	inp := {"azure": {"storage": {"accounts": [{}]}}}

	test.assert_empty(check.deny) with input as inp
}
