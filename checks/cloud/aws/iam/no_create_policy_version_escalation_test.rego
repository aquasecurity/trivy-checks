package builtin.aws.iam.aws0347_test

import rego.v1

import data.builtin.aws.iam.aws0347 as check

test_deny_create_policy_version if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:CreatePolicyVersion"],
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

test_allow_no_dangerous_action if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject"],
			"Resource": ["arn:aws:s3:::my-bucket/*"],
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
			"Action": ["iam:CreatePolicyVersion"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) == 0
}

test_allow_constrained_resource if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:CreatePolicyVersion"],
			"Resource": ["arn:aws:iam::123456789012:policy/MyPolicy"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) == 0
}
