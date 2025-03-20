package builtin.aws.iam.aws0345

import rego.v1

test_with_allow_s3_full_access if {
	policies := [{
		"name": "policy_with_s3_full_access",
		"document": {"value": "{\"Version\":\"2012-10-17\",\"Id\":\"\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{},\"NotPrincipal\":{},\"Action\":[\"s3:*\"],\"NotAction\":null,\"Resource\":[\"*\"],\"NotResource\":null,\"Condition\":{}}]}"},
	}]

	r := deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 1
}

test_with_deny_s3_full_access if {
	policies := [{
		"name": "policy_with_s3_full_access",
		"document": {"value": "{\"Version\":\"2012-10-17\",\"Id\":\"\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Deny\",\"Principal\":{},\"NotPrincipal\":{},\"Action\":[\"s3:*\"],\"NotAction\":null,\"Resource\":[\"*\"],\"NotResource\":null,\"Condition\":{}}]}"},
	}]

	r := deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 0
}

test_with_no_s3_full_access if {
	policies := [{
		"name": "policy_without_s3_full_access",
		"document": {"value": "{\"Version\":\"2012-10-17\",\"Id\":\"\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{},\"NotPrincipal\":{},\"Action\":[\"s3:GetObject\"],\"NotAction\":null,\"Resource\":[\"arn:aws:s3:::examplebucket/*\"],\"NotResource\":null,\"Condition\":{}}]}"},
	}]

	r := deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 0
}

test_with_role_using_amazon_s3_full_access_policy if {
	roles := [{
		"name": "role_with_amazon_s3_full_access",
		"policies": [{"document": {"value": "{\"Version\":\"2012-10-17\",\"Id\":\"\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{},\"NotPrincipal\":{},\"Action\":[\"s3:*\"],\"NotAction\":null,\"Resource\":[\"*\"],\"NotResource\":null,\"Condition\":{}}]}"}}],
	}]

	r := deny with input as {"aws": {"iam": {"roles": roles}}}
	count(r) == 1
}

test_with_role_not_using_amazon_s3_full_access_policy if {
	roles := [{
		"name": "role_without_amazon_s3_full_access",
		"policies": [{"document": {"value": "{\"Version\":\"2012-10-17\",\"Id\":\"\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{},\"NotPrincipal\":{},\"Action\":[\"s3:GetObject\"],\"NotAction\":null,\"Resource\":[\"arn:aws:s3:::examplebucket/*\"],\"NotResource\":null,\"Condition\":{}}]}"}}],
	}]

	r := deny with input as {"aws": {"iam": {"roles": roles}}}
	count(r) == 0
}
