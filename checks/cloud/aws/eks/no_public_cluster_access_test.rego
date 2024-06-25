package builtin.aws.eks.aws0040_test

import rego.v1

import data.builtin.aws.eks.aws0040 as check
import data.lib.test

test_deny_public_access_enabled if {
	inp := {"aws": {"eks": {"clusters": [{"publicaccessenabled": {"value": true}}]}}}

	test.assert_equal_message("public access should be enabled", check.deny) with input as inp
}

test_allow_public_access_disabled if {
	inp := {"aws": {"eks": {"clusters": [{"publicaccessenabled": {"value": false}}]}}}

	test.assert_empty(check.deny) with input as inp
}
