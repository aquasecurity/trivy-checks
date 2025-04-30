package builtin.google.gke.google0063_test

import rego.v1

import data.builtin.google.gke.google0063 as check

test_deny_auto_repair_disabled if {
	inp := {"google": {"gke": {"clusters": [{"nodepools": [{"management": {"enableautorepair": {"value": false}}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_auto_repair_disabled_for_autopilot if {
	inp := {"google": {"gke": {"clusters": [{
		"enableautpilot": {"value": true},
		"autoscaling": {"autoprovisioningdefaults": {"management": {"enableautorepair": {"value": false}}}},
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_auto_repair_missing_for_autopilot if {
	inp := {"google": {"gke": {"clusters": [{"enableautpilot": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_auto_repair_enabled if {
	inp := {"google": {"gke": {"clusters": [{"nodepools": [{"management": {"enableautorepair": {"value": true}}}]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_auto_repair_enabled_for_autopilot if {
	inp := {"google": {"gke": {"clusters": [{
		"enableautpilot": {"value": true},
		"autoscaling": {"autoprovisioningdefaults": {"management": {"enableautorepair": {"value": true}}}},
	}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_auto_repair_unresolvable_for_autopilot if {
	inp := {"google": {"gke": {"clusters": [{
		"enableautpilot": {"value": true},
		"autoscaling": {"autoprovisioningdefaults": {"management": {"enableautorepair": {"value": false, "unresolvable": true}}}},
	}]}}}

	res := check.deny with input as inp
	res == set()
}
