package builtin.aws.ecr.aws0032_test

import rego.v1

import data.builtin.aws.ecr.aws0032 as check
import data.lib.test

test_allow_without_public_access if {
	inp := {"aws": {"ecr": {"repositories": [{"policies": [{"document": {"value": json.marshal({"Statement": [{
		"Action": ["ecr:*"],
		"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
		"Effect": "Allow",
	}]})}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_with_public_access_all if {
	inp := {"aws": {"ecr": {"repositories": [{"policies": [{"document": {"value": json.marshal({"Statement": [{
		"Action": ["ecr:*"],
		"Principal": "*",
	}]})}}]}]}}}

	test.assert_equal_message("Policy provides public access to the ECR repository", check.deny) with input as inp
}

test_deny_with_public_acces_any if {
	inp := {"aws": {"ecr": {"repositories": [{"policies": [{"document": {"value": json.marshal({"Statement": [{
		"Action": ["ecr:*"],
		"Principal": {"AWS": ["*"]},
		"Effect": "Allow",
	}]})}}]}]}}}

	test.assert_equal_message("Policy provides public access to the ECR repository", check.deny) with input as inp
}
