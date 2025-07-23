package builtin.google.storage.google0077

import rego.v1

import data.builtin.google.storage.google0077 as check

test_allow_bucket_with_logging if {
	inp := {"google": {"storage": {"buckets": [{"logging": {"logbucket": {"value": "my-log-bucket"}}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_bucket_without_logging if {
	inp := {"google": {"storage": {"buckets": [{"logging": {}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
