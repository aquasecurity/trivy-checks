package builtin.aws.eks.aws0038_test

import rego.v1

import data.builtin.aws.eks.aws0038 as check
import data.lib.test

test_allow_all_logging_enabled if {
	inp := {"aws": {"eks": {"clusters": [{"logging": {
		"api": {"value": true},
		"audit": {"value": true},
		"authenticator": {"value": true},
		"controllermanager": {"value": true},
		"scheduler": {"value": true},
	}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_all_logging_disabled if {
	inp := {"aws": {"eks": {"clusters": [{"logging": {
		"audit": {"value": false},
		"authenticator": {"value": false},
		"controllermanager": {"value": false},
		"scheduler": {"value": false},
	}}]}}}

	test.assert_count(check.deny, 5) with input as inp
}

test_deny_one_logging_disabled if {
	inp := {"aws": {"eks": {"clusters": [{"logging": {
		"api": {"value": true},
		"audit": {"value": false},
		"authenticator": {"value": true},
		"controllermanager": {"value": true},
		"scheduler": {"value": true},
	}}]}}}

	test.assert_equal_message("Control plane audit logging is not enabled.", check.deny) with input as inp
}
