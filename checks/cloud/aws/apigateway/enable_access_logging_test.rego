package builtin.aws.apigateway.aws0001_test

import rego.v1

import data.builtin.aws.apigateway.aws0001 as check
import data.lib.test

test_deny_api_gateway_without_log_group_arn if {
	inp := {"aws": {"apigateway": {"v1": {"apis": [{"stages": [{"accesslogging": {"cloudwatchloggrouparn": {"value": ""}}}]}]}}}}
	test.assert_count(check.deny, 1) with input as inp
}

test_allow_api_gateway_with_log_group_arn if {
	inp := {"aws": {"apigateway": {"v1": {"apis": [{"stages": [{"accesslogging": {"cloudwatchloggrouparn": {"value": "log-group-arn"}}}]}]}}}}
	test.assert_empty(check.deny) with input as inp
}
