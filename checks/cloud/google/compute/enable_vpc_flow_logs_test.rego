package builtin.google.compute.google0029_test

import rego.v1

import data.builtin.google.compute.google0029 as check
import data.lib.test

test_deny_vpc_flow_logs_disabled if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{"enableflowlogs": {"value": false}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_vpc_flow_logs_is_not_specified if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_vpc_flow_logs_enabled if {
	inp := {"google": {"compute": {"networks": [{"subnetworks": [{"enableflowlogs": {"value": true}}]}]}}}

	res := check.deny with input as inp
	res == set()
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
