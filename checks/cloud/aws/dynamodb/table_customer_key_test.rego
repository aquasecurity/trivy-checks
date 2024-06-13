package builtin.aws.dynamodb.aws0025_test

import rego.v1

import data.builtin.aws.dynamodb.aws0025 as check
import data.lib.test

test_allow_table_with_cmk if {
	inp := {"aws": {"dynamodb": {"tables": [{
		"name": "test",
		"serversideencryption": {
			"enabled": {"value": true},
			"kmskeyid": {"value": "alias/test"},
		},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_table_without_cmk if {
	inp := {"aws": {"dynamodb": {"tables": [{
		"name": "test",
		"serversideencryption": {
			"enabled": {"value": true},
			"kmskeyid": {"value": ""},
		},
	}]}}}

	test.assert_equal_message("Table encryption explicitly uses the default KMS key.", check.deny) with input as inp
}

test_deny_table_sse_disabled if {
	inp := {"aws": {"dynamodb": {"tables": [{
		"name": "test",
		"serversideencryption": {
			"enabled": {"value": false},
			"kmskeyid": {"value": ""},
		},
	}]}}}

	test.assert_equal_message("Table encryption explicitly uses the default KMS key.", check.deny) with input as inp
}
