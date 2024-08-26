package builtin.google.gke.google0056_test

import rego.v1

import data.builtin.google.gke.google0056 as check
import data.lib.test

test_deny_network_policy_disabled if {
	inp := {"google": {"gke": {"clusters": [{"networkpolicy": {"enabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_network_policy_enabled if {
	inp := {"google": {"gke": {"clusters": [{
		"networkpolicy": {"enabled": {"value": true}},
		"enableautpilot": {"value": false},
		"datapathprovider": {"value": ""},
	}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_network_policy_disabled_but_autopilot_enabled if {
	inp := {"google": {"gke": {"clusters": [{
		"networkpolicy": {"enabled": {"value": false}},
		"enableautpilot": {"value": true},
		"datapathprovider": {"value": ""},
	}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_network_policy_disabled_but_dataplanev2_enabled if {
	inp := {"google": {"gke": {"clusters": [{
		"networkpolicy": {"enabled": {"value": false}},
		"enableautpilot": {"value": false},
		"datapathprovider": {"value": "ADVANCED_DATAPATH"},
	}]}}}

	res := check.deny with input as inp
	res == set()
}
