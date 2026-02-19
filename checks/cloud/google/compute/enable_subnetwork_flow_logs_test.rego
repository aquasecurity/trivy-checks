package builtin.google.compute.google0076_test

import rego.v1

import data.builtin.google.compute.google0076 as check
import data.lib.test

test_deny_subnetwork_flow_logs_explicitly_disabled if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{"enableflowlogs": {"value": false}}]}]}}}

	res := check.deny with input as inp
	test.assert_equal_message("Subnetwork does not have flow logs enabled.", res)
}

test_deny_subnetwork_flow_logs_not_specified if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{}]}]}}}

	res := check.deny with input as inp
	test.assert_equal_message("Subnetwork does not have flow logs configured.", res)
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

test_allow_vpc_flow_logs_disabled_for_proxy_only if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [
		{
			"enableflowlogs": {"value": false},
			"purpose": {"value": "REGIONAL_MANAGED_PROXY"},
		},
		{
			"enableflowlogs": {"value": false},
			"purpose": {"value": "GLOBAL_MANAGED_PROXY"},
		},
	]}]}}}

	res := check.deny with input as inp
	res == set()
}
