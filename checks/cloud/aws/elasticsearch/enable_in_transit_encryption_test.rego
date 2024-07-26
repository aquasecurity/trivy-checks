package builtin.aws.elasticsearch.aws0043_test

import rego.v1

import data.builtin.aws.elasticsearch.aws0043 as check
import data.lib.test

test_allow_encryption_enabled if {
	inp := {"aws": {"elasticsearch": {"domains": [{"transitencryption": {"enabled": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_encryption_disabled if {
	inp := {"aws": {"elasticsearch": {"domains": [{"transitencryption": {"enabled": {"value": false}}}]}}}

	test.assert_equal_message("Domain does not have in-transit encryption enabled.", check.deny) with input as inp
}
