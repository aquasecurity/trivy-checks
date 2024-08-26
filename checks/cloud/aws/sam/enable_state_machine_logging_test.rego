package builtin.aws.sam.aws0119_test

import rego.v1

import data.builtin.aws.sam.aws0119 as check
import data.lib.test

test_deny_logging_disabled if {
	inp := {"aws": {"sam": {"statemachines": [{"loggingconfiguration": {"loggingenabled": {"value": false}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_logging_enabled if {
	inp := {"aws": {"sam": {"statemachines": [{"loggingconfiguration": {"loggingenabled": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
