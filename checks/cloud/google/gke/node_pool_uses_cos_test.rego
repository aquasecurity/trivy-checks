package builtin.google.gke.google0054_test

import rego.v1

import data.builtin.google.gke.google0054 as check

test_deny_cluster_node_config_image_type_is_ubuntu if {
	inp := {"google": {"gke": {"clusters": [{"nodeconfig": {"imagetype": {"value": "UBUNTU"}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_node_pool_image_type_is_ubuntu if {
	inp := {"google": {"gke": {"clusters": [{"nodepools": [{"nodeconfig": {"imagetype": {"value": "UBUNTU"}}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_autopilot_image_type_is_ubuntu if {
	inp := {"google": {"gke": {"clusters": [{
		"enableautpilot": {"value": true},
		"autoscaling": {"autoprovisioningdefaults": {"imagetype": {"value": "UBUNTU"}}},
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_node_config_image_type_is_cos if {
	inp := {"google": {"gke": {"clusters": [{"nodeconfig": {"imagetype": {"value": "COS"}}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_node_pool_image_type_is_cos if {
	inp := {"google": {"gke": {"clusters": [{"nodepools": [{"nodeconfig": {"imagetype": {"value": "COS"}}}]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_autopilot_image_type_is_cos if {
	inp := {"google": {"gke": {"clusters": [{
		"enableautpilot": {"value": true},
		"autoscaling": {"autoprovisioningdefaults": {"imagetype": {"value": "COS"}}},
	}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_autopilot_image_type_is_unresolvable if {
	inp := {"google": {"gke": {"clusters": [{
		"enableautpilot": {"value": true},
		"autoscaling": {"autoprovisioningdefaults": {"imagetype": {"value": "", "unresolvable": true}}},
	}]}}}

	res := check.deny with input as inp
	res == set()
}
