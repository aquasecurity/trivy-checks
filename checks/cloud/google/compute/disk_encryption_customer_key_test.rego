package builtin.google.compute.google0034_test

import rego.v1

import data.builtin.google.compute.google0034 as check
import data.lib.test

test_deny_disk_is_not_encrypted if {
	inp := {"google": {"compute": {"disks": [{"encryption": {"kmskeylink": {"value": ""}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_disk_encryption_is_not_specified if {
	inp := {"google": {"compute": {"disks": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_disk_is_encrypted if {
	inp := {"google": {"compute": {"disks": [{"encryption": {"kmskeylink": {"value": "something"}}}]}}}
	res := check.deny with input as inp
	res == set()
}
