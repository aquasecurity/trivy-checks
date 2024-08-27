package builtin.aws.apigateway.aws0190_test

import rego.v1

import data.builtin.aws.apigateway.aws0190 as check
import data.lib.test

test_allow_cache_enabled if {
	test.assert_empty(check.deny) with input as build_input(true)
}

test_deny_cache_disabled if {
	test.assert_count(check.deny, 1) with input as build_input(false)
}

build_input(cacheenabled) := {"aws": {"apigateway": {"v1": {"apis": [{"stages": [{"restmethodsettings": [{"cacheenabled": {"value": cacheenabled}}]}]}]}}}}
