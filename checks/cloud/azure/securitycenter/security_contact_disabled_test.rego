package builtin.azure.securitycenter.azure0064_test

import rego.v1

import data.builtin.azure.securitycenter.azure0064 as check

test_deny_contact_disabled if {
	res := check.deny with input as build_input_with_enabled(false)
	count(res) == 1
}

test_allow_contact_missing_enabled_field if {
	res := check.deny with input as build_input_no_enabled_field
	count(res) == 0
}

test_allow_contact_enabled if {
	res := check.deny with input as build_input_with_enabled(true)
	count(res) == 0
}

test_allow_multiple_contacts_all_enabled if {
	res := check.deny with input as build_input_multiple_contacts_enabled
	count(res) == 0
}

test_deny_multiple_contacts_some_disabled if {
	res := check.deny with input as build_input_mixed_contacts
	count(res) == 1
}

build_input_with_enabled(enabled) := {"azure": {"securitycenter": {"contacts": [{
	"isenabled": {"value": enabled},
	"email": {"value": "security@example.com"},
}]}}}

build_input_no_enabled_field := {"azure": {"securitycenter": {"contacts": [{"email": {"value": "security@example.com"}}]}}}

build_input_multiple_contacts_enabled := {"azure": {"securitycenter": {"contacts": [
	{
		"isenabled": {"value": true},
		"email": {"value": "security1@example.com"},
	},
	{
		"isenabled": {"value": true},
		"email": {"value": "security2@example.com"},
	},
]}}}

build_input_mixed_contacts := {"azure": {"securitycenter": {"contacts": [
	{
		"isenabled": {"value": true},
		"email": {"value": "security1@example.com"},
	},
	{
		"isenabled": {"value": false},
		"email": {"value": "security2@example.com"},
	},
]}}}
