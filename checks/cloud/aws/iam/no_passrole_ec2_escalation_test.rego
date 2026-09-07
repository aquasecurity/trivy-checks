package builtin.aws.iam.aws0350_test

import rego.v1

import data.builtin.aws.iam.aws0350 as check

test_deny_passrole_ec2_combo if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:PassRole", "ec2:RunInstances"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) > 0
}

test_deny_passrole_ec2_separate_statements if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": ["iam:PassRole"],
				"Resource": ["*"],
			},
			{
				"Effect": "Allow",
				"Action": ["ec2:RunInstances"],
				"Resource": ["*"],
			},
		],
	})}}]}}}

	results := check.deny with input as inp
	count(results) > 0
}

test_deny_with_wildcards if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:*", "ec2:*"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) > 0
}

test_allow_missing_passrole if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["ec2:RunInstances"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) == 0
}

test_allow_missing_ec2 if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:PassRole"],
			"Resource": ["*"],
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
			"Action": ["iam:PassRole", "ec2:RunInstances"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) == 0
}
