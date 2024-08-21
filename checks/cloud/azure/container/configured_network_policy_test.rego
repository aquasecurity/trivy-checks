package builtin.azure.container.azure0043_test

import rego.v1

import data.builtin.azure.container.azure0043 as check
import data.lib.test

test_deny_cluster_without_network_policy if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"networkprofile": {"networkpolicy": {"value": ""}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_cluster_with_network_policy_is_not_specified if {
	inp := {"azure": {"container": {"kubernetesclusters": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_cluster_with_network_policy if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"networkprofile": {"networkpolicy": {"value": "calico"}}}]}}}
	res := check.deny with input as inp
	res == set()
}
