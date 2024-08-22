package builtin.azure.appservice.azure0006_test

import rego.v1

import data.builtin.azure.appservice.azure0006 as check
import data.lib.test

test_deny_minimum_tls_version_is_tls1_0 if {
	inp := {"azure": {"appservice": {"services": [{"site": {"minimumtlsversion": {"value": "1.0"}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_minimum_tls_version_not_specified if {
	inp := {"azure": {"appservice": {"services": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_minimum_tls_version_is_tls1_2 if {
	inp := {"azure": {"appservice": {"services": [{"site": {"minimumtlsversion": {"value": check.recommended_tls_version}}}]}}}
	res := check.deny with input as inp
	res == set()
}
