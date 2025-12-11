package builtin.azure.network.azure0073_test

import rego.v1

import data.builtin.azure.network.azure0073 as check

test_deny_network_watcher_flow_disabled if {
	inp := {"azure": {"network": {"networkwatcherflowlogs": [{"enabled": {"value": false}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_network_watcher_flow_enabled if {
	inp := {"azure": {"network": {"networkwatcherflowlogs": [{"enabled": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
