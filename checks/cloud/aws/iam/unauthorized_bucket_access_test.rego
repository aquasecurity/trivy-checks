package builtin.aws.iam.aws0346_test

import data.builtin.aws.iam.aws0346 as check

import rego.v1

test_deny_policy_with_s3_get_and_put_wildcards if {
	policies := [{
		"name": {"value": "policy_with_literal_get_and_put"},
		"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": ["s3:get*", "s3:put*"],
				"Resource": "*",
			}],
		})},
	}]

	r := check.deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 1
}

test_allow_policy_with_denied_actions_on_s3_wildcards if {
	policies := [{
		"name": {"value": "policy_with_literal_get_and_put"},
		"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Deny",
				"Action": ["s3:get*", "s3:put*"],
				"Resource": "*",
			}],
		})},
	}]

	r := check.deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 0
}

test_allow_s3_only_get if {
	policies := [{
		"name": {"value": "policy_with_only_get"},
		"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": ["s3:get*"],
				"Resource": "*",
			}],
		})},
	}]

	r := check.deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 0
}

test_allow_s3_get_and_put_limited_resource if {
	policies := [{
		"name": {"value": "policy_with_get_and_put_limited_resource"},
		"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": ["s3:GetObject", "s3:PutObject"],
				"Resource": ["arn:aws:s3:::specificbucket/*"],
			}],
		})},
	}]

	r := check.deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 0
}
