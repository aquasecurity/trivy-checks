package builtin.google.storage.google0002_test

import rego.v1

import data.builtin.google.storage.google0002 as check
import data.lib.test

test_allow_uniform_bucket_level_access_enabled if {
	inp := {"google": {"storage": {"buckets": [{
		"__defsec_metadata": {"managed": true},
		"enableuniformbucketlevelaccess": {"value": true},
	}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_uniform_bucket_level_access_disabled if {
	inp := {"google": {"storage": {"buckets": [{
		"__defsec_metadata": {"managed": true},
		"enableuniformbucketlevelaccess": {"value": false},
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
