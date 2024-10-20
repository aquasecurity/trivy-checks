package builtin.google.storage.google0066_test

import rego.v1

import data.builtin.google.storage.google0066 as check
import data.lib.test

test_allow_bucket_with_customer_key if {
	inp := {"google": {"storage": {"buckets": [{"encryption": {"defaultkmskeyname": {"value": "key"}}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_bucket_without_customer_key if {
	inp := {"google": {"storage": {"buckets": [{"encryption": {"defaultkmskeyname": {"value": ""}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
