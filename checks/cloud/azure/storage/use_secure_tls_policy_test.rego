package builtin.azure.storage.azure0011_test

import rego.v1

import data.builtin.azure.storage.azure0011 as check
import data.lib.test

test_deny_tls_1_0 if {
	inp := {"azure": {"storage": {"accounts": [{"minimumtlsversion": {"value": "TLS1_0"}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_tls_1_2 if {
	inp := {"azure": {"storage": {"accounts": [{"minimumtlsversion": {"value": "TLS1_2"}}]}}}

	test.assert_empty(check.deny) with input as inp
}
