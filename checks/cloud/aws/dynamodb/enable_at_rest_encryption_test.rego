package builtin.aws.dynamodb.aws0023_test

import rego.v1

import data.builtin.aws.dynamodb.aws0023 as check
import data.lib.test

test_allow_with_encryption if {
	inp := {"aws": {"dynamodb": {"daxclusters": [{"serversideencryption": {"enabled": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_disallow_without_encryption if {
	inp := {"aws": {"dynamodb": {"daxclusters": [{"serversideencryption": {"enabled": {"value": false}}}]}}}

	test.assert_equal_message("DAX encryption is not enabled.", check.deny) with input as inp
}
