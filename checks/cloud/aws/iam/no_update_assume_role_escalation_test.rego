package builtin.aws.iam.aws0352_test

import rego.v1

import data.builtin.aws.iam.aws0352 as check

test_deny_update_assume_role_policy if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:UpdateAssumeRolePolicy"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) > 0
}

test_deny_iam_wildcard if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:*"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) > 0
}

test_deny_full_wildcard if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["*"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) > 0
}

test_allow_constrained_resource if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:UpdateAssumeRolePolicy"],
			"Resource": ["arn:aws:iam::123456789012:role/specific-role"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) == 0
}

test_allow_deny_effect if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Action": ["iam:UpdateAssumeRolePolicy"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) == 0
}

test_allow_safe_action if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["sts:AssumeRole"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) == 0
}
