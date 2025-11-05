package builtin.azure.securitycenter.azure0062_test

import rego.v1

import data.builtin.azure.securitycenter.azure0062 as check

test_deny_security_center_contact_without_email if {
	res := check.deny with input as build_input("")
	count(res) == 1
}

test_deny_security_center_contact_no_email_field if {
	res := check.deny with input as build_input_no_email
	count(res) == 1
}

test_allow_security_center_contact_with_email if {
	res := check.deny with input as build_input("contact@example.com")
	count(res) == 0
}

build_input(email) := {"azure": {"securitycenter": {"contacts": [{"email": {"value": email}}]}}}

build_input_no_email := {"azure": {"securitycenter": {"contacts": [{}]}}}
