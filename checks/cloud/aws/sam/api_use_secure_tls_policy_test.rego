package builtin.aws.sam.aws0112_test

import rego.v1

import data.builtin.aws.sam.aws0112 as check
import data.lib.test

test_deny_tls_v_1_0 if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "TLS_1_0"}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_tls_v_1_2 if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "TLS_1_2"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

# Every remaining SecurityPolicy value documented for
# AWS::ApiGateway::DomainName. All of them negotiate TLS 1.2 or higher, so
# none should be reported as an outdated policy.
test_allow_enhanced_security_policies if {
	every policy in {
		"SecurityPolicy_TLS13_1_3_2025_09",
		"SecurityPolicy_TLS13_1_3_FIPS_2025_09",
		"SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09",
		"SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09",
		"SecurityPolicy_TLS13_1_2_PQ_2025_09",
		"SecurityPolicy_TLS13_1_2_2021_06",
		"SecurityPolicy_TLS13_2025_EDGE",
		"SecurityPolicy_TLS12_PFS_2025_EDGE",
		"SecurityPolicy_TLS12_2018_EDGE",
	} {
		test.assert_empty(check.deny) with input as {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": policy}}}]}}}
	}
}

# An unrecognised value is reported rather than assumed safe, so a policy AWS
# adds later surfaces for review instead of passing silently.
test_deny_unknown_policy if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "SecurityPolicy_Not_A_Real_Value"}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}
