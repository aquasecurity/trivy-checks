package builtin.azure.synapse.azure0034_test

import rego.v1

import data.builtin.azure.synapse.azure0034 as check
import data.lib.test

test_deny_managed_virtual_network_disabled if {
	inp := {"azure": {"synapse": {"workspaces": [{"enablemanagedvirtualnetwork": {"value": false}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_managed_virtual_network_enabled if {
	inp := {"azure": {"synapse": {"workspaces": [{"enablemanagedvirtualnetwork": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
