package builtin.aws.iam.aws0123_test

import rego.v1

import data.builtin.aws.iam.aws0123 as check
import data.lib.test

test_allow_group_with_mfa if {
	test.assert_empty(check.deny) with input as build_condition({
		"StringLike": {"kms:ViaService": "timestream.*.amazonaws.com"},
		"Bool": {"aws:MultiFactorAuthPresent": "true"},
	})
}

test_disallow_group_without_mfa if {
	test.assert_equal_message("Multi-Factor authentication is not enforced for group", check.deny) with input as build_condition({})
}

build_condition(body) = {"aws": {"iam": {"groups": [{"policies": [{"document": {"value": json.marshal({"Statement": [{"Condition": body}]})}}]}]}}}
