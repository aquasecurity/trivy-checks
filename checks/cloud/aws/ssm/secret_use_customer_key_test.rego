package builtin.aws.ssm.aws0098_test

import rego.v1

import data.builtin.aws.ssm.aws0098 as check
import data.lib.test

test_deny_without_kms_key if {
	inp := {"aws": {"ssm": {"secrets": [{"kmskeyid": {"value": ""}}]}}}

	test.assert_equal_message("Secret is not encrypted with a customer managed key.", check.deny) with input as inp
}

test_deny_with_default_kms_key if {
	inp := {"aws": {"ssm": {"secrets": [{"kmskeyid": {"value": "alias/aws/secretsmanager"}}]}}}

	test.assert_equal_message("Secret explicitly uses the default key.", check.deny) with input as inp
}

test_allow_with_custom_kms_key if {
	inp := {"aws": {"ssm": {"secrets": [{"kmskeyid": {"value": "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"}}]}}}

	test.assert_empty(check.deny) with input as inp
}
