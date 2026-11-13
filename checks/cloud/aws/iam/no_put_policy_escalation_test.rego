package builtin.aws.iam.aws0351_test

import rego.v1

import data.builtin.aws.iam.aws0351 as check

test_deny_put_user_policy if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:PutUserPolicy"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) > 0
}

test_deny_put_role_policy if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:PutRolePolicy"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) > 0
}

test_deny_put_group_policy if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:PutGroupPolicy"],
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

test_allow_constrained_resource if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:PutUserPolicy"],
			"Resource": ["arn:aws:iam::123456789012:user/specific-user"],
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
			"Action": ["iam:PutUserPolicy"],
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
			"Action": ["s3:PutObject"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) == 0
}
