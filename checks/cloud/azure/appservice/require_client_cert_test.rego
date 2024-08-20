package builtin.azure.appservice.azure0001_test

import rego.v1

import data.builtin.azure.appservice.azure0001 as check
import data.lib.test

test_deny_service_client_cert_disabled if {
	inp := {"azure": {"appservice": {"services": [{"enableclientcert": {"value": false}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_service_client_cert_not_specified if {
	inp := {"azure": {"appservice": {"services": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_service_client_cert_enabled if {
	inp := {"azure": {"appservice": {"services": [{"enableclientcert": {"value": true}}]}}}
	res := check.deny with input as inp
	res == set()
}
