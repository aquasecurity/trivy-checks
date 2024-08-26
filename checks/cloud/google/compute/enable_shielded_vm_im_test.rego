package builtin.google.compute.google0045_test

import rego.v1

import data.builtin.google.compute.google0045 as check
import data.lib.test

test_deny_instance_shielded_vm_integrity_monitoring_disabled if {
	inp := {"google": {"compute": {"instances": [{"shieldedvm": {"integritymonitoringenabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_instance_shielded_vm_integrity_monitoring_enabled if {
	inp := {"google": {"compute": {"instances": [{"shieldedvm": {"integritymonitoringenabled": {"value": true}}}]}}}

	res := check.deny with input as inp
	res == set()
}
