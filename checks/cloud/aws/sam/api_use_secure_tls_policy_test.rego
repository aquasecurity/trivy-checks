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
