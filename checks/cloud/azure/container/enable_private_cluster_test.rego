package builtin.azure.container.azure0065_test

import rego.v1

import data.builtin.azure.container.azure0065 as check

test_deny_private_cluster_disabled if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"enableprivatecluster": {"value": false}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_private_cluster_not_specified if {
	inp := {"azure": {"container": {"kubernetesclusters": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_private_cluster_enabled if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"enableprivatecluster": {"value": true}}]}}}
	res := check.deny with input as inp
	res == set()
}
