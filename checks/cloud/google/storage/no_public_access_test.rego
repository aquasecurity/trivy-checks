package builtin.google.storage.google0001_test

import rego.v1

import data.builtin.google.storage.google0001 as check
import data.lib.test

test_allow_bucket_does_not_allow_public_access if {
	inp := build_input({
		"__defsec_metadata": {"managed": true},
		"bindings": [{"members": [{"value": "user:zKqzW@example.com"}]}],
	})
	res := check.deny with input as inp
	res == set()
}

test_deny_bucket_allows_public_access_members if {
	inp := build_input({
		"__defsec_metadata": {"managed": true},
		"bindings": [{"members": [{"value": "allAuthenticatedUsers"}]}],
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_bucket_allows_public_access_bindings if {
	inp := build_input({
		"__defsec_metadata": {"managed": true},
		"bindings": [{"members": [{"value": "allAuthenticatedUsers"}]}],
	})

	res := check.deny with input as inp
	count(res) == 1
}

build_input(bucket) := {"google": {"storage": {"buckets": [bucket]}}}
