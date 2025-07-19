package builtin.google.compute.google0076_test

import rego.v1

import data.builtin.google.compute.google0076 as check

test_deny_subnetwork_flow_logs_explicitly_disabled if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{"enableflowlogs": {"value": false}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_subnetwork_flow_logs_not_specified if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_subnetwork_flow_logs_enabled if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{"enableflowlogs": {"value": true}}]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_multiple_subnetworks_mixed_flow_logs if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [
		{"enableflowlogs": {"value": true}},
		{"enableflowlogs": {"value": false}},
		{},
	]}]}}}

	res := check.deny with input as inp
	count(res) == 2
}
