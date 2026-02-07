package builtin.azure.storage.azure0059_test

import rego.v1

import data.builtin.azure.storage.azure0059 as check
import data.lib.test

test_deny_https_disabled if {
	inp := {"azure": {"storage": {"accounts": [{
		"enforcehttps": {"value": false},
		"minimumtlsversion": {"value": "TLS1_2"},
	}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_insecure_tls_version if {
	inp := {"azure": {"storage": {"accounts": [{
		"enforcehttps": {"value": true},
		"minimumtlsversion": {"value": "TLS1_0"},
	}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_tls_version_not_configured if {
	inp := {"azure": {"storage": {"accounts": [{"enforcehttps": {"value": true}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_https_and_secure_tls1_2 if {
	inp := {"azure": {"storage": {"accounts": [{
		"enforcehttps": {"value": true},
		"minimumtlsversion": {"value": "TLS1_2"},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_https_and_secure_tls1_3 if {
	inp := {"azure": {"storage": {"accounts": [{
		"enforcehttps": {"value": true},
		"minimumtlsversion": {"value": "TLS1_3"},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}
