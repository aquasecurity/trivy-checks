package builtin.aws.sqs.aws0135_test

import rego.v1

import data.builtin.aws.sqs.aws0135 as check
import data.lib.test

test_allow_encrypted_with_cmk if {
	inp := {"aws": {"sqs": {"queues": [{
		"name": "test-queue",
		"encryption": {"kmskeyid": {"value": "key-id"}},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_unencrypted_with_cmk if {
	inp := {"aws": {"sqs": {"queues": [{
		"name": "test-queue",
		"encryption": {"kmskeyid": {"value": "alias/aws/sqs"}},
	}]}}}

	test.assert_equal_message("Queue is not encrypted with a customer managed key.", check.deny) with input as inp
}
