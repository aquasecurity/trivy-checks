package builtin.aws.iam.aws0058_test

import rego.v1

import data.builtin.aws.iam.aws0058 as check
import data.lib.test

test_allow_policy_require_lowercase_in_passwords if {
	inp := {"aws": {"iam": {"passwordpolicy": {"requirelowercase": {"value": true}}}}}

	test.assert_empty(check.deny) with input as inp
}

test_disallow_policy_no_require_lowercase_in_passwords if {
	inp := {"aws": {"iam": {"passwordpolicy": {"requirelowercase": {"value": false}}}}}

	test.assert_equal_message("Password policy does not require lowercase characters", check.deny) with input as inp
}
