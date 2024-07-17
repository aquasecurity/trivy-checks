package builtin.google.compute.google0033_test

import rego.v1

import data.builtin.google.compute.google0033 as check
import data.lib.test

test_deny_instance_boot_disk_is_not_encrypted if {
	inp := {"google": {"compute": {"instances": [{"bootdisks": [{"encryption": {"kmskeylink": {"value": ""}}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_instance_attached_disk_is_not_encrypted if {
	inp := {"google": {"compute": {"instances": [{"attacheddisks": [{"encryption": {}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_instance_disks_is_encrypted if {
	inp := {"google": {"compute": {
		"bootdisks": [{"encryption": {"kmskeylink": {"value": "kms-key-link"}}}],
		"attacheddisks": [{"disk": {"encryption": {"kmskeylink": {"value": "kms-key-link"}}}}],
	}}}

	res := check.deny with input as inp
	res == set()
}
