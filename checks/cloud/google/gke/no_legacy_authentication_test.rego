package builtin.google.gke.google0064_test

import rego.v1

import data.builtin.google.gke.google0064 as check
import data.lib.test

test_deny_master_auth_by_certificate if {
	inp := {"google": {"gke": {"clusters": [{"masterauth": {"clientcertificate": {"issuecertificate": {"value": true}}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_master_auth_by_username_password if {
	inp := {"google": {"gke": {"clusters": [{"masterauth": {"username": {"value": "username"}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_legacy_auth_disabled if {
	inp := {"google": {"gke": {"clusters": [{"masterauth": {
		"clientcertificate": {"issuecertificate": {"value": false}},
		"username": {"value": ""},
	}}]}}}

	res := check.deny with input as inp
	res == set()
}
