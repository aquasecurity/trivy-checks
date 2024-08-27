package builtin.aws.apigateway.aws0004_test

import rego.v1

import data.builtin.aws.apigateway.aws0004 as check
import data.lib.test

test_deny_get_method_without_auth if {
	inp := input_with_method({"httpmethod": {"value": "GET"}, "authorizationtype": {"value": "NONE"}})
	test.assert_count(check.deny, 1) with input as inp
}

test_allow_option_method if {
	test.assert_empty(check.deny) with input as input_with_method({"httpmethod": {"value": "OPTION"}})
}

test_allow_get_method_with_auth if {
	test.assert_empty(check.deny) with input as input_with_method({"methods": [{"httpmethod": {"value": "GET"}, "authorizationtype": {"value": "AWS_IAM"}}]})
}

test_allow_if_api_required if {
	test.assert_empty(check.deny) with input as input_with_method({"httpmethod": {"value": "GET"}, "authorizationtype": {"value": "AWS_IAM"}})
}

input_with_method(method) = {"aws": {"apigateway": {"v1": {"apis": [{"resources": [{"methods": [method]}]}]}}}}
