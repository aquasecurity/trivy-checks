package builtin.aws.ecr.aws0033_test

import rego.v1

import data.builtin.aws.ecr.aws0033 as check
import data.lib.test

test_allow_repo_with_kms if {
	inp := {"aws": {"ecr": {"repositories": [{"encryption": {
		"type": {"value": "KMS"},
		"kmskeyid": {"value": "key"},
	}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_repo_without_kms_encryption if {
	inp := {"aws": {"ecr": {"repositories": [{"encryption": {"type": {"value": "AES256"}}}]}}}

	test.assert_equal_message("Repository is not encrypted using KMS.", check.deny) with input as inp
}

test_deny_repo_with_kms_encryption_without_key if {
	inp := {"aws": {"ecr": {"repositories": [{"encryption": {
		"type": {"value": "KMS"},
		"kmskeyid": {"value": ""},
	}}]}}}

	test.assert_equal_message("Repository encryption does not use a customer managed KMS key.", check.deny) with input as inp
}
