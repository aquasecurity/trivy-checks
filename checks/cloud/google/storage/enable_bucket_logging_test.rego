package builtin.google.storage.google0077

import rego.v1

import data.builtin.google.storage.google0077 as check

test_allow_bucket_with_logging if {
	inp := {"google": {"storage": {"buckets": [{"name": {"value": "test-bucket"}, "logging": {"logbucket": {"value": "my-log-bucket"}}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_bucket_without_logging if {
	inp := {"google": {"storage": {"buckets": [{"name": {"value": "test-bucket"}, "logging": {}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_bucket_used_as_log_bucket if {
	# Bucket that is used as a log bucket by another bucket should be allowed
	# even if it doesn't have its own logging configured
	inp := {"google": {"storage": {"buckets": [
		{
			"name": {"value": "app-bucket"},
			"logging": {"logbucket": {"value": "log-bucket"}},
		},
		{
			"name": {"value": "log-bucket"},
			"logging": {},
		},
	]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_bucket_without_logging_not_used_as_log_bucket if {
	# Bucket without logging that is not used as a log bucket should be denied
	inp := {"google": {"storage": {"buckets": [
		{
			"name": {"value": "app-bucket"},
			"logging": {},
		},
		{
			"name": {"value": "another-bucket"},
			"logging": {"logbucket": {"value": "some-other-log-bucket"}},
		},
	]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_mixed_scenario if {
	# Mixed scenario: some buckets with logging, some without, some used as log buckets
	inp := {"google": {"storage": {"buckets": [
		{
			"name": {"value": "app-bucket-1"},
			"logging": {"logbucket": {"value": "log-bucket"}},
		},
		{
			"name": {"value": "app-bucket-2"},
			"logging": {"logbucket": {"value": "log-bucket"}},
		},
		{
			"name": {"value": "log-bucket"},
			"logging": {},
		},
		{
			"name": {"value": "bad-bucket"},
			"logging": {},
		},
	]}}}

	res := check.deny with input as inp
	count(res) == 1 # Only bad-bucket should be flagged
}
