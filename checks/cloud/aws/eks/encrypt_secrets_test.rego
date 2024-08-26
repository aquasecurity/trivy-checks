package builtin.aws.eks.aws0039_test

import rego.v1

import data.builtin.aws.eks.aws0039 as check
import data.lib.test

test_deny_without_secrets_and_kms if {
	inp := {"aws": {"eks": {"clusters": [{"encryption": {
		"kmskeyid": {"value": ""},
		"secrets": {"value": false},
	}}]}}}

	test.assert_equal_message("Cluster does not have secret encryption enabled.", check.deny) with input as inp
}

test_deny_with_secrets_but_no_kms if {
	inp := {"aws": {"eks": {"clusters": [{"encryption": {
		"kmskeyid": {"value": ""},
		"secrets": {"value": true},
	}}]}}}

	test.assert_equal_message("Cluster encryption requires a KMS key ID, which is missing", check.deny) with input as inp
}

test_allow_with_secrets_and_kms if {
	inp := {"aws": {"eks": {"clusters": [{"encryption": {
		"kmskeyid": {"value": "test"},
		"secrets": {"value": true},
	}}]}}}

	test.assert_empty(check.deny) with input as inp
}
