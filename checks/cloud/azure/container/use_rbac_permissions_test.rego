package builtin.azure.container.azure0042_test

import rego.v1

import data.builtin.azure.container.azure0042 as check
import data.lib.test

test_deny_rbac_disabled if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"rolebasedaccesscontrol": {"enabled": {"value": false}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_rbac_is_not_specified if {
	inp := {"azure": {"container": {"kubernetesclusters": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_rbac_enabled if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"rolebasedaccesscontrol": {"enabled": {"value": true}}}]}}}
	res := check.deny with input as inp
	res == set()
}
