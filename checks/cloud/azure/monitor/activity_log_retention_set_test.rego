package builtin.azure.monitor.azure0031_test

import rego.v1

import data.builtin.azure.monitor.azure0031 as check
import data.lib.test

test_deny_retention_policy_disabled if {
	inp := {"azure": {"monitor": {"logprofiles": [{"retentionpolicy": {"enabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_retention_policy_enabled_but_days_lt_365 if {
	inp := {"azure": {"monitor": {"logprofiles": [{"retentionpolicy": {
		"enabled": {"value": true},
		"days": {"value": 30},
	}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_retention_policy_enabled_and_days_gt_365 if {
	inp := {"azure": {"monitor": {"logprofiles": [{"retentionpolicy": {
		"enabled": {"value": true},
		"days": {"value": 365},
	}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
