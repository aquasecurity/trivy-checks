package builtin.google.storage.google0078

import rego.v1

import data.builtin.google.storage.google0078 as check

test_allow_bucket_with_versioning if {
	inp := {"google": {"storage": {"buckets": [{"versioning": {"enabled": {"value": true}}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_bucket_without_versioning if {
	inp := {"google": {"storage": {"buckets": [{"versioning": {"enabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
