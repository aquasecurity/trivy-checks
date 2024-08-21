package builtin.azure.appservice.azure0005_test

import rego.v1

import data.builtin.azure.appservice.azure0005 as check
import data.lib.test

test_deny_http2_disabled if {
	inp := {"azure": {"appservice": {"services": [{"site": {"enablehttp2": {"value": false}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_http2_enabled if {
	inp := {"azure": {"appservice": {"services": [{"site": {"enablehttp2": {"value": true}}}]}}}
	res := check.deny with input as inp
	res == set()
}
