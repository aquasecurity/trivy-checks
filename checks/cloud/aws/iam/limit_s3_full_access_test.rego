package builtin.aws.iam.aws0345

import rego.v1

test_with_allow_s3_full_access if {
	policies := [{
		"name": {"value": "policy_with_s3_full_access"},
		"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": ["s3:*"],
				"Resource": ["*"],
			}],
		})},
	}]

	r := deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 1
}

test_with_allow_s3_full_access_with_verb_non_mixed if {
	policies := [{
		"name": {"value": "policy_with_s3_full_access"},
		"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Deny",
					"Action": ["s3:get*"],
					"Resource": ["*"],
				},
				{
					"Effect": "Allow",
					"Action": ["s3:*"],
					"Resource": ["*"],
				},
			],
		})},
	}]

	r := deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 1
}

test_with_allow_s3_full_access_overriden_by_deny if {
	policies := [{
		"name": {"value": "policy_with_s3_full_access"},
		"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Deny",
					"Action": ["s3:*"],
					"Resource": ["*"],
				},
				{
					"Effect": "Allow",
					"Action": ["s3:*"],
					"Resource": ["*"],
				},
			],
		})},
	}]

	r := deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 0
}

test_with_deny_s3_full_access if {
	policies := [{
		"name": {"value": "policy_with_s3_full_access"},
		"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Deny",
				"Action": ["s3:*"],
			}],
		})},
	}]

	r := deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 0
}

test_with_no_s3_full_access if {
	policies := [{
		"name": {"value": "policy_without_s3_full_access"},
		"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": ["s3:GetObject"],
				"Resource": ["arn:aws:s3:::examplebucket/*"],
			}],
		})},
	}]

	r := deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 0
}

test_with_role_using_amazon_s3_full_access_policy if {
	roles := [{
		"name": {"value": "role_with_amazon_s3_full_access"},
		"policies": [{"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": ["s3:*"],
				"Resource": ["*"],
			}],
		})}}],
	}]

	r := deny with input as {"aws": {"iam": {"roles": roles}}}
	count(r) == 1
}

test_with_role_not_using_amazon_s3_full_access_policy if {
	roles := [{
		"name": {"value": "role_without_amazon_s3_full_access"},
		"policies": [{"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": ["s3:GetObject"],
				"Resource": ["arn:aws:s3:::examplebucket"],
			}],
		})}}],
	}]

	r := deny with input as {"aws": {"iam": {"roles": roles}}}
	count(r) == 0
}
