package builtin.google.iam.google0004_test

import rego.v1

import data.builtin.google.iam.google0004 as check
import data.lib.test

service_email := "123-compute@developer.gserviceaccount.com"

proper_email := "proper@account.com"

test_deny_default_service_account_enabled_for_folder_member if {
	inp := build_input({"members": [{
		"defaultserviceaccount": {"value": true},
		"member": {"value": proper_email},
	}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_default_service_account_enabled_for_folder_binding if {
	inp := build_input({"bindings": [{
		"includesdefaultserviceaccount": {"value": true},
		"members": [{"value": proper_email}],
	}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_default_member_for_folder_member if {
	inp := build_input({"members": [{
		"defaultserviceaccount": {"value": false},
		"member": {"value": service_email},
	}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_default_member_for_folder_binding if {
	inp := build_input({"bindings": [{
		"includesdefaultserviceaccount": {"value": false},
		"members": [{"value": service_email}],
	}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_default_service_account_disabled if {
	inp := build_input({
		"members": [{
			"defaultserviceaccount": {"value": false},
			"member": {"value": proper_email},
		}],
		"bindings": [{
			"includesdefaultserviceaccount": {"value": false},
			"members": [{"value": proper_email}],
		}],
	})

	res := check.deny with input as inp
	res == set()
}

build_input(folder) := {"google": {"iam": {"folders": [folder]}}}
