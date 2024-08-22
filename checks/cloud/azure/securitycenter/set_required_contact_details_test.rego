package builtin.azure.securitycenter.azure0046_test

import rego.v1

import data.builtin.azure.securitycenter.azure0046 as check
import data.lib.test

test_deny_contact_without_phone if {
	inp := {"azure": {"securitycenter": {"contacts": [{"phone": {"value": ""}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_contact_with_phone if {
	inp := {"azure": {"securitycenter": {"contacts": [{"phone": {"value": "555-555-5555"}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
