package builtin.azure.container.azure0040_test

import rego.v1

import data.builtin.azure.container.azure0040 as check
import data.lib.test

test_deny_logging_via_oms_agent_disabled if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"addonprofile": {"omsagent": {"enabled": {"value": false}}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_logging_via_oms_agent_is_not_specified if {
	inp := {"azure": {"container": {"kubernetesclusters": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_logging_via_oms_agent_enabled if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"addonprofile": {"omsagent": {"enabled": {"value": true}}}}]}}}
	res := check.deny with input as inp
	res == set()
}
