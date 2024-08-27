package builtin.aws.apigateway.aws0002_test

import rego.v1

import data.builtin.aws.apigateway.aws0002 as check
import data.lib.test

test_allow_api_gateway_with_cache_encryption if {
	test.assert_empty(check.deny) with input as build_input(true)
}

test_deny_api_gateway_without_cache_encryption if {
	test.assert_count(check.deny, 1) with input as build_input(false)
}

build_input(cachedataencrypted) := {"aws": {"apigateway": {"v1": {"apis": [{"stages": [{"restmethodsettings": [{
	"cacheenabled": {"value": true},
	"cachedataencrypted": {"value": cachedataencrypted},
}]}]}]}}}}
