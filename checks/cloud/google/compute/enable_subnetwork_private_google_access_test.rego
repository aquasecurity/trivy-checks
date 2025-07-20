package builtin.google.compute.google0075_test

import rego.v1

import data.builtin.google.compute.google0075 as check

test_deny_private_google_access_explicitly_disabled if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{"privateipgoogleaccess": {
		"value": false,
		"explicit": true,
	}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_private_google_access_not_configured if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{"privateipgoogleaccess": {
		"value": false,
		"explicit": false,
	}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_private_google_access_enabled if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{"privateipgoogleaccess": {
		"value": true,
		"explicit": true,
	}}]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_private_google_access_default_true_regardless_of_value if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{"privateipgoogleaccess": {
		"value": false,
		"explicit": false,
	}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
