package builtin.azure.container.azure0066_test

import rego.v1

import data.builtin.azure.container.azure0066 as check

test_deny_azure_policy_disabled if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"addonprofile": {"azurepolicy": {"enabled": {"value": false}}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_azure_policy_not_specified if {
	inp := {"azure": {"container": {"kubernetesclusters": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_azure_policy_enabled if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"addonprofile": {"azurepolicy": {"enabled": {"value": true}}}}]}}}
	res := check.deny with input as inp
	res == set()
}
