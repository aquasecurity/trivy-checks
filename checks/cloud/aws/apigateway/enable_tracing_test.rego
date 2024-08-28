package builtin.aws.apigateway.aws0003_test

import rego.v1

import data.builtin.aws.apigateway.aws0003 as check
import data.lib.test

test_allow_tracing_enabled if {
	test.assert_empty(check.deny) with input as build_input(true)
}

test_deny_tracing_disabled if {
	test.assert_count(check.deny, 1) with input as build_input(false)
}

build_input(xraytracingenabled) := {"aws": {"apigateway": {"v1": {"apis": [{"stages": [{"xraytracingenabled": {"value": xraytracingenabled}}]}]}}}}
