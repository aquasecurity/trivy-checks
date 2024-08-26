package builtin.google.compute.google0039_test

import rego.v1

import data.builtin.google.compute.google0039 as check
import data.lib.test

test_deny_ssl_policy_minimum_tls_version_is_1 if {
	inp := {"google": {"compute": {"sslpolicies": [{"minimumtlsversion": {"value": "TLS_1_0"}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_ssl_policy_minimum_tls_version_is_1_2 if {
	inp := {"google": {"compute": {"sslpolicies": [{"minimumtlsversion": {"value": check.tls_v_1_2}}]}}}

	res := check.deny with input as inp
	res == set()
}
