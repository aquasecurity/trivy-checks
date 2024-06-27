package builtin.aws.lambda.aws0067_test

import rego.v1

import data.builtin.aws.lambda.aws0067 as check
import data.lib.test

test_allow_with_arn if {
	inp := {"aws": {"lambda": {"functions": [{"permissions": [{
		"principal": {"value": "sns.amazonaws.com"},
		"sourcearn": {"value": "arn"},
	}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_without_arn if {
	inp := {"aws": {"lambda": {"functions": [{"permissions": [{
		"principal": {"value": "sns.amazonaws.com"},
		"sourcearn": {"value": ""},
	}]}]}}}

	test.assert_equal_message("Lambda permission lacks source ARN for *.amazonaws.com principal.", check.deny) with input as inp
}
