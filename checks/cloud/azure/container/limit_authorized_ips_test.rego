package builtin.azure.container.azure0041_test

import rego.v1

import data.builtin.azure.container.azure0041 as check
import data.lib.test

test_deny_authorized_ip_ranges_undefined if {
	inp := {"azure": {"container": {"kubernetesclusters": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_authorized_ip_ranges_defined if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"apiserverauthorizedipranges": [{"value": "1.2.3.4/32"}]}]}}}
	res := check.deny with input as inp
	res == set()
}

test_allow_authorized_ip_ranges_undefined_for_private_cluster if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"enableprivatecluster": {"value": true}}]}}}
	res := check.deny with input as inp
	res == set()
}
