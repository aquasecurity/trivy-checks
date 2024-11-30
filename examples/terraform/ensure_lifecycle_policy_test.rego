package user.terraform.ensure_lifecycle_policy_test

import rego.v1

import data.user.terraform.ensure_lifecycle_policy as check

test_allow_bucket_has_lifecycle_policy if {
	inp := {"aws": {"s3": {"buckets": [{
		"name": {"value": "test"},
		"lifecycleconfiguration": [{"status": {"value": "enabled"}}],
	}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_bucket_without_lifecycle_policies if {
	inp := {"aws": {"s3": {"buckets": [{"name": {"value": "test"}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
