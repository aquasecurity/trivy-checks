package builtin.google.compute.google0041_test

import rego.v1

import data.builtin.google.compute.google0041 as check
import data.lib.test

test_deny_instance_shielded_vm_vptm_disabled if {
	inp := {"google": {"compute": {"instances": [{"shieldedvm": {"vtpmenabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_instance_shielded_vm_vptm_enabled if {
	inp := {"google": {"compute": {"instances": [{"shieldedvm": {"vtpmenabled": {"value": true}}}]}}}

	res := check.deny with input as inp
	res == set()
}
