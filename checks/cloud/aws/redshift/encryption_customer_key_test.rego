package builtin.aws.redshift.aws0084_test

import rego.v1

import data.builtin.aws.redshift.aws0084 as check
import data.lib.test

test_deny_encryption_disabled if {
	inp := {"aws": {"redshift": {"clusters": [{"encryption": {
		"enabled": {"value": false},
		"kmskeyid": {"value": "some-key"},
	}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_missing_kms_key if {
	inp := {"aws": {"redshift": {"clusters": [{"encryption": {
		"enabled": {"value": true},
		"kmskeyid": {"value": ""},
	}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_cluster_encrypted_with_kms_key if {
	inp := {"aws": {"redshift": {"clusters": [{"encryption": {
		"enabled": {"value": true},
		"kmskeyid": {"value": "some-key"},
	}}]}}}

	test.assert_empty(check.deny) with input as inp
}
