package builtin.azure.network.azure0049_test

import rego.v1

import data.builtin.azure.network.azure0049 as check
import data.lib.test

test_deny_flow_log_retention_policy_disabled if {
	inp := {"azure": {"network": {"networkwatcherflowlogs": [{"retentionpolicy": {"enabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_flow_log_retention_policy_less_than_90 if {
	inp := {"azure": {"network": {"networkwatcherflowlogs": [{"retentionpolicy": {
		"enabled": {"value": true},
		"days": {"value": 89},
	}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_flow_log_retention_policy_greater_than_90 if {
	inp := {"azure": {"network": {"networkwatcherflowlogs": [{"retentionpolicy": {
		"enabled": {"value": true},
		"days": {"value": 90},
	}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
