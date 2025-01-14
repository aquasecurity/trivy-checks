package builtin.aws.msk.aws0179_test

import rego.v1

import data.builtin.aws.msk.aws0179 as check
import data.lib.test

test_deny_at_rest_encryption_disabled if {
	inp := {"aws": {"msk": {"clusters": [{}]}}}
	test.assert_count(check.deny, 1) with input as inp
}

test_deny_at_rest_encryption_enabled if {
	inp := {"aws": {"msk": {"clusters": [{"encryptionatrest": {"enabled": {"value": true}}}]}}}
	test.assert_empty(check.deny) with input as inp
}
