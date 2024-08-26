package builtin.google.iam.google0006_test

import rego.v1

import data.builtin.google.iam.google0006 as check
import data.lib.test

test_deny_default_service_account_enabled_for_folder_member if {
	inp := build_input({"members": [{
		"defaultserviceaccount": {"value": true},
		"member": {"value": "proper@email.com"},
	}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_default_service_account_enabled_for_folder_binding if {
	inp := build_input({"bindings": [{
		"includesdefaultserviceaccount": {"value": true},
		"members": [{"value": "proper@email.com"}],
	}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_default_member_for_folder_member if {
	inp := build_input({"members": [{
		"defaultserviceaccount": {"value": false},
		"member": {"value": "123-compute@developer.gserviceaccount.com"},
	}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_default_member_for_folder_binding if {
	inp := build_input({"bindings": [{
		"includesdefaultserviceaccount": {"value": false},
		"members": [{"value": "123-compute@developer.gserviceaccount.com"}],
	}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_default_service_account_disabled if {
	inp := build_input({
		"members": [{
			"defaultserviceaccount": {"value": false},
			"member": {"value": "proper@account.com"},
		}],
		"bindings": [{
			"includesdefaultserviceaccount": {"value": false},
			"members": [{"value": "proper@account.com"}],
		}],
	})

	res := check.deny with input as inp
	res == set()
}

build_input(project) := {"google": {"iam": {"projects": [project]}}}
