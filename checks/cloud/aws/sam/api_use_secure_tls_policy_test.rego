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

test_allow_security_policy_tls13_1_2_2021_06 if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "SecurityPolicy_TLS13_1_2_2021_06"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_security_policy_tls13_1_3_2025_09 if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "SecurityPolicy_TLS13_1_3_2025_09"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_security_policy_tls13_1_3_fips_2025_09 if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "SecurityPolicy_TLS13_1_3_FIPS_2025_09"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_security_policy_tls13_1_2_pfs_pq_2025_09 if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_security_policy_tls13_1_2_fips_pq_2025_09 if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_security_policy_tls13_1_2_fips_pfs_pq_2025_09 if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_security_policy_tls13_1_2_pq_2025_09 if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "SecurityPolicy_TLS13_1_2_PQ_2025_09"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_security_policy_tls13_2025_edge if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "SecurityPolicy_TLS13_2025_EDGE"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_security_policy_tls12_pfs_2025_edge if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "SecurityPolicy_TLS12_PFS_2025_EDGE"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_security_policy_tls12_2018_edge if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {"value": "SecurityPolicy_TLS12_2018_EDGE"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_unresolvable_security_policy if {
	inp := {"aws": {"sam": {"apis": [{"domainconfiguration": {"securitypolicy": {}}}]}}}

	test.assert_empty(check.deny) with input as inp
}