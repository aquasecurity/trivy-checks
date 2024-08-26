package builtin.google.iam.google0008_test

import rego.v1

import data.builtin.google.iam.google0008 as check
import data.lib.test

test_deny_default_member_for_org_binding if {
	inp := build_input({"bindings": [{
		"includesdefaultserviceaccount": {"value": false},
		"members": [{"value": "123-compute@developer.gserviceaccount.com"}],
	}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_default_service_account_for_org_binding if {
	inp := build_input({"bindings": [{
		"includesdefaultserviceaccount": {"value": true},
		"members": [{"value": "proper@email.com"}],
	}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_default_service_account_for_org_member if {
	inp := build_input({"members": [{"defaultserviceaccount": {"value": true}}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_default_member_for_org_member if {
	inp := build_input({"members": [{
		"defaultserviceaccount": {"value": false},
		"member": {"value": "123-compute@developer.gserviceaccount.com"},
	}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_proper_member if {
	inp := build_input({
		"members": [{
			"member": {"value": "proper@email.com"},
			"defaultserviceaccount": {"value": false},
		}],
		"bindings": [{
			"includesdefaultserviceaccount": {"value": false},
			"members": [{"value": "proper@email.com"}],
		}],
	})

	res := check.deny with input as inp
	res == set()
}

build_input(org) := {"google": {"iam": {"organizations": [org]}}}
