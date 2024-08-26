package builtin.aws.sqs.aws0097_test

import rego.v1

import data.builtin.aws.sqs.aws0097 as check
import data.lib.test

test_allow_without_wildcards if {
	inp := {"aws": {"sqs": {"queues": [{"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["sqs:CreateQueue"],
		}],
	})}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_with_wildcards_but_not_allowed if {
	inp := {"aws": {"sqs": {"queues": [{"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Action": ["sqs:*"],
		}],
	})}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_with_wildcards if {
	inp := {"aws": {"sqs": {"queues": [{"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["*"],
		}],
	})}}]}]}}}

	test.assert_equal_message("Queue policy does not restrict actions to a known set.", check.deny) with input as inp
}
