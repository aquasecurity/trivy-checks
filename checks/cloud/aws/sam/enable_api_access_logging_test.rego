package builtin.aws.sam.aws0113_test

import rego.v1

import data.builtin.aws.sam.aws0113 as check
import data.lib.test

test_deny_api_logging_not_configured if {
	inp := {"aws": {"sam": {"apis": [{"accesslogging": {"cloudwatchloggrouparn": {"value": ""}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_api_logging_not_configured if {
	inp := {"aws": {"sam": {"apis": [{"accesslogging": {"cloudwatchloggrouparn": {"value": "foo"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
