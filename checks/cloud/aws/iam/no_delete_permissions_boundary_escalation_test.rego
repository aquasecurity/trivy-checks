package builtin.aws.iam.aws0353_test

import rego.v1

import data.builtin.aws.iam.aws0353 as check

test_deny_delete_user_permissions_boundary if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:DeleteUserPermissionsBoundary"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) > 0
}

test_deny_delete_role_permissions_boundary if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:DeleteRolePermissionsBoundary"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) > 0
}

test_deny_scoped_resource if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["iam:DeleteUserPermissionsBoundary"],
			"Resource": ["arn:aws:iam::123456789012:user/specific-user"],
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

test_allow_deny_effect if {
	inp := {"aws": {"iam": {"policies": [{"document": {"value": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Action": ["iam:DeleteUserPermissionsBoundary"],
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
			"Action": ["iam:CreateUser"],
			"Resource": ["*"],
		}],
	})}}]}}}

	results := check.deny with input as inp
	count(results) == 0
}
