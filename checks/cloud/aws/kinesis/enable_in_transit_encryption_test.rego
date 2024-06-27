package builtin.aws.kinesis.aws0064_test

import rego.v1

import data.builtin.aws.kinesis.aws0064 as check
import data.lib.test

test_deny_unecrypted if {
	inp := {"aws": {"kinesis": {"streams": [{
		"name": "test",
		"encryption": {
			"type": {"value": ""},
			"kmskeyid": {"value": ""},
		},
	}]}}}

	test.assert_equal_message("Stream does not use KMS encryption.", check.deny) with input as inp
}

test_deny_with_kms_but_without_key if {
	inp := {"aws": {"kinesis": {"streams": [{
		"name": "test",
		"encryption": {
			"type": {"value": "KMS"},
			"kmskeyid": {"value": ""},
		},
	}]}}}

	test.assert_equal_message("Stream does not use a custom-managed KMS key.", check.deny) with input as inp
}

test_allow_encrypted if {
	inp := {"aws": {"kinesis": {"streams": [{
		"name": "test",
		"encryption": {
			"type": {"value": "KMS"},
			"kmskeyid": {"value": "test"},
		},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}
