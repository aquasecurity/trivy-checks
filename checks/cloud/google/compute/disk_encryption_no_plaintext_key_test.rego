package builtin.google.compute.google0037_test

import rego.v1

import data.builtin.google.compute.google0037 as check
import data.lib.test

test_deny_disk_with_plaintext_encryption_key if {
	inp := {"google": {"compute": {"disks": [{"encryption": {"rawkey": {"value": "b2ggbm8gdGhpcyBpcyBiYWQ"}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_instance_boot_disk_with_plaintext_encryption_key if {
	inp := {"google": {"compute": {"instances": [{"bootdisks": [{"encryption": {"rawkey": {"value": "b2ggbm8gdGhpcyBpcyBiYWQ"}}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_instance_attached_disk_with_plaintext_encryption_key if {
	inp := {"google": {"compute": {"instances": [{"attacheddisks": [{"encryption": {"rawkey": {"value": "b2ggbm8gdGhpcyBpcyBiYWQ"}}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_disks_without_plaintext_encryption_key if {
	inp := {"google": {"compute": {
		"disks": [{"encryption": {"rawkey": {"value": ""}}}],
		"instances": [{
			"bootdisks": [{"encryption": {"rawkey": {"value": ""}}}],
			"attacheddisks": [{"encryption": {"rawkey": {"value": ""}}}],
		}],
	}}}

	res := check.deny with input as inp
	res == set()
}
