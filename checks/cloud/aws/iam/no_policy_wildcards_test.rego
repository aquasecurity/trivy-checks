package builtin.aws.iam.aws0057_test

import rego.v1

import data.builtin.aws.iam.aws0057 as check
import data.lib.test

allowed_actions := {"sqs:ListQueues": {}}

test_deny_wildcard_resource if {
	inp := build_input(false, {
		"Effect": "Allow",
		"Action": ["s3:ListBucket"],
		"Resource": ["arn:aws:s3:::*"],
		"Principal": {"AWS": ["arn:aws:iam::1234567890:root"]},
	})

	test.assert_equal_message(`IAM policy document uses sensitive action "" on wildcarded resource "arn:aws:s3:::*"`, check.deny) with input as inp with data.aws.iam.allowed_actions as allowed_actions
}

test_allow_wildcard_resource_with_allowed_action if {
	inp := build_input(false, {
		"Effect": "Allow",
		"Action": ["sqs:ListQueues"],
		"Resource": ["arn:aws:sqs:*:123456789012:alice_queue_*"],
		"Principal": {"AWS": ["arn:aws:iam::1234567890:root"]},
	})

	test.assert_empty(check.deny) with input as inp with data.aws.iam.allowed_actions as allowed_actions
}

test_allow_builtin_policy_with_wildcard_resource if {
	inp := build_input(true, {
		"Effect": "Allow",
		"Action": ["s3:ListBucket"],
		"Resource": ["arn:aws:s3:::*"],
		"Principal": {"AWS": ["arn:aws:iam::1234567890:root"]},
	})

	test.assert_empty(check.deny) with input as inp with data.aws.iam.allowed_actions as allowed_actions
}

test_deny_wildcard_action if {
	inp := build_input(false, {
		"Effect": "Allow",
		"Action": ["s3:*"],
		"Resource": ["arn:aws:s3:::bucket-name"],
		"Principal": {"AWS": ["arn:aws:iam::1234567890:root"]},
	})
	test.assert_equal_message(`IAM policy document uses wildcarded action "s3:*"`, check.deny) with input as inp with data.aws.iam.allowed_actions as allowed_actions
}

test_allow_policy_without_wildcards if {
	inp := build_input(false, {
		"Effect": "Allow",
		"Action": ["s3:GetObject"],
		"Resource": ["arn:aws:s3:::bucket-name"],
		"Principal": {"AWS": ["arn:aws:iam::1234567890:root"]},
	})
}

test_allow_wildcard_resource_for_cloudwatch_log_group if {
	inp := build_input(false, {
		"Effect": "Allow",
		"Action": ["logs:CreateLogStream"],
		"Resource": ["arn:aws:logs:us-west-2:123456789012:log-group:SampleLogGroupName:*"],
	})
	test.assert_empty(check.deny) with input as inp with data.aws.iam.allowed_actions as allowed_actions
}

test_deny_wildcard_resource_for_cloudwatch_log_stream if {
	inp := build_input(false, {
		"Effect": "Allow",
		"Action": ["logs:CreateLogStream"],
		"Resource": ["*"],
	})

	test.assert_equal_message("IAM policy document uses sensitive action \"logs:CreateLogStream\" on wildcarded resource \"arn:aws:logs:us-west-2:123456789012:log-group:SampleLogGroupName:*\"", check.deny) with input as inp with data.aws.iam.allowed_actions as allowed_actions
}

test_deny_issues_with_multiple_policies if {
	inp := {"aws": {"iam": {"policies": [
		{
			"builtin": {"value": false},
			"document": {"value": json.marshal({"Statement": [{
				"Effect": "Allow",
				"Action": ["s3:*"],
				"Resource": ["arn:aws:s3:::bucket-name"],
				"Principal": {"AWS": ["arn:aws:iam::1234567890:root"]},
			}]})},
		},
		{
			"builtin": {"value": false},
			"document": {"value": json.marshal({"Statement": [{
				"Effect": "Allow",
				"Action": ["s3:ListBucket"],
				"Resource": ["arn:aws:s3:::*"],
				"Principal": {"AWS": ["arn:aws:iam::1234567890:root"]},
			}]})},
		},
	]}}}

	test.assert_count(check.deny, 2) with input as inp with data.aws.iam.allowed_actions as allowed_actions
}

build_input(builtin, statement) := {"aws": {"iam": {"policies": [{
	"builtin": {"value": builtin},
	"document": {"value": json.marshal({"Statement": [statement]})},
}]}}}
