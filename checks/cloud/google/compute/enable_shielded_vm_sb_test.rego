package builtin.google.compute.google0067_test

import rego.v1

import data.builtin.google.compute.google0067 as check
import data.lib.test

test_deny_instance_shielded_vm_secure_boot_disabled if {
	inp := {"google": {"compute": {"instances": [{"shieldedvm": {"securebootenabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_instance_shielded_vm_secure_boot_enabled if {
	inp := {"google": {"compute": {"instances": [{"shieldedvm": {"securebootenabled": {"value": true}}}]}}}

	res := check.deny with input as inp
	res == set()
}
