package builtin.aws.sns.aws0095_test

import rego.v1

import data.builtin.aws.sns.aws0095 as check
import data.lib.test

test_deny_topic_without_encryption if {
	inp := {"aws": {"sns": {"topics": [{"encryption": {"kmskeyid": {"value": ""}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_topic_with_encryption if {
	inp := {"aws": {"sns": {"topics": [{"encryption": {"kmskeyid": {"value": "foo"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_topic_without_encryption_but_unresolvable if {
	inp := {"aws": {"sns": {"topics": [{"encryption": {"kmskeyid": {"value": "", "unresolvable": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
