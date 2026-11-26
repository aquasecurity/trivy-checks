package builtin.google.gke.google0061_test

import rego.v1

import data.builtin.google.gke.google0061 as check

test_deny_master_networks_disabled if {
	inp := {"google": {"gke": {"clusters": [{
		"masterauthorizednetworks": {"enabled": {"value": false}},
		"controlplaneendpoints": {"ipendpoints": {"enabled": {"value": true}}},
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_master_networks_enabled if {
	inp := {"google": {"gke": {"clusters": [{"masterauthorizednetworks": {"enabled": {"value": true}}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_master_networks_enabled_with_ip_endpoints_enabled if {
	inp := {"google": {"gke": {"clusters": [{
		"masterauthorizednetworks": {"enabled": {"value": true}},
		"controlplaneendpoints": {"ipendpoints": {"enabled": {"value": true}}},
	}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_ip_endpoints_disabled if {
	inp := {"google": {"gke": {"clusters": [{
		"masterauthorizednetworks": {"enabled": {"value": false}},
		"controlplaneendpoints": {"ipendpoints": {"enabled": {"value": false}}},
	}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_ip_endpoints_unresolvable if {
	inp := {"google": {"gke": {"clusters": [{
		"masterauthorizednetworks": {"enabled": {"value": false}},
		"controlplaneendpoints": {"ipendpoints": {"enabled": {"value": false, "unresolvable": true}}},
	}]}}}

	res := check.deny with input as inp
	res == set()
}
