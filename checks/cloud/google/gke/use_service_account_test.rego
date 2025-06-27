package builtin.google.gke.google0050_test

import rego.v1

import data.builtin.google.gke.google0050 as check

test_deny_node_config_with_default_service_account if {
	inp := {"google": {"gke": {"clusters": [{
		"removedefaultnodepool": {"value": false},
		"nodeconfig": {"serviceaccount": {"value": ""}},
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_node_config_override_default_service_account if {
	inp := {"google": {"gke": {"clusters": [{
		"removedefaultnodepool": {"value": false},
		"nodeconfig": {"serviceaccount": {"value": "service-account"}},
	}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_node_pool_with_default_service_account if {
	inp := {"google": {"gke": {"clusters": [{
		"removedefaultnodepool": {"value": true},
		"nodepools": [{"nodeconfig": {"serviceaccount": {"value": ""}}}],
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_node_pool_with_override_default_service_account if {
	inp := {"google": {"gke": {"clusters": [{
		"removedefaultnodepool": {"value": true},
		"nodepools": [{"nodeconfig": {"serviceaccount": {"value": "service-account"}}}],
	}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_autopilot_with_default_service_account if {
	inp := {"google": {"gke": {"clusters": [{
		"enableautpilot": {"value": true},
		"autoscaling": {"autoprovisioningdefaults": {"serviceaccount": {"value": ""}}},
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_alow_autopilot_overrided_service_account if {
	inp := {"google": {"gke": {"clusters": [{
		"enableautpilot": {"value": true},
		"autoscaling": {"autoprovisioningdefaults": {"serviceaccount": {"value": "service-account"}}},
	}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_deny_nap_with_default_service_account if {
	inp := {"google": {"gke": {"clusters": [{"autoscaling": {
		"enabled": {"value": true},
		"autoprovisioningdefaults": {"serviceaccount": {"value": ""}},
	}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
