package builtin.aws.neptune.aws0128_test

import rego.v1

import data.builtin.aws.neptune.aws0128 as check
import data.lib.test

test_deny_missing_kms_key if {
	inp := {"aws": {"neptune": {"clusters": [{"kmskeyid": {"value": ""}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_with_kms_key if {
	inp := {"aws": {"neptune": {"clusters": [{"kmskeyid": {"value": "key"}}]}}}

	test.assert_empty(check.deny) with input as inp
}
