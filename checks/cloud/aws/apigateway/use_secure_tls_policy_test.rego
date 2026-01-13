package builtin.aws.apigateway.aws0005_test

import rego.v1

import data.builtin.aws.apigateway.aws0005 as check
import data.lib.test

test_allow_with_legacy_TLS_1_2 if {
	test.assert_empty(check.deny) with input as {"aws": {"apigateway": {"v1": {"domainnames": [{"securitypolicy": {"value": "TLS_1_2"}}]}}}}
}

test_allow_with_SecurityPolicy_TLS12_PFS_2025_EDGE if {
	test.assert_empty(check.deny) with input as {"aws": {"apigateway": {"v1": {"domainnames": [{"securitypolicy": {"value": "SecurityPolicy_TLS12_PFS_2025_EDGE"}}]}}}}
}

test_allow_with_SecurityPolicy_TLS13_2025_EDGE if {
	test.assert_empty(check.deny) with input as {"aws": {"apigateway": {"v1": {"domainnames": [{"securitypolicy": {"value": "SecurityPolicy_TLS13_2025_EDGE"}}]}}}}
}

test_allow_with_SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09 if {
	test.assert_empty(check.deny) with input as {"aws": {"apigateway": {"v1": {"domainnames": [{"securitypolicy": {"value": "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09"}}]}}}}
}

test_deny_with_tls_1_0 if {
	inp := {"aws": {"apigateway": {"v1": {"domainnames": [{"securitypolicy": {"value": "TLS_1_0"}}]}}}}
	test.assert_count(check.deny, 1) with input as inp
}
