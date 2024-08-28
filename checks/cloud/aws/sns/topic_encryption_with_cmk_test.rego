package builtin.aws.sns.aws0136_test

import rego.v1

import data.builtin.aws.sns.aws0136 as check
import data.lib.test

test_allow_topic_without_encryption if {
	inp := {"aws": {"sns": {"topics": [{"encryption": {"kmskeyid": {"value": ""}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_topic_with_default_kms_key if {
	inp := {"aws": {"sns": {"topics": [{"encryption": {"kmskeyid": {"value": check.default_kms_key}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_topic_with_custom_kms_key if {
	inp := {"aws": {"sns": {"topics": [{"encryption": {"kmskeyid": {"value": "foo"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
