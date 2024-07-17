package builtin.google.gke.google0057_test

import rego.v1

import data.builtin.google.gke.google0057 as check
import data.lib.test

test_deny_cluster_node_pools_metadata_exposed_by_default if {
	inp := {"google": {"gke": {"clusters": [{"nodeconfig": {"workloadmetadataconfig": {"nodemetadata": {"value": "UNSPECIFIED"}}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_node_pool_metadata_exposed if {
	inp := {"google": {"gke": {"clusters": [{"nodepools": [{"nodeconfig": {"workloadmetadataconfig": {"nodemetadata": {"value": "UNSPECIFIED"}}}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_node_pools_metadata_secured if {
	inp := {"google": {"gke": {"clusters": [{
		"nodeconfig": {"workloadmetadataconfig": {"nodemetadata": {"value": "SECURE"}}},
		"nodepools": [{"workloadmetadataconfig": {"nodemetadata": {"value": "SECURE"}}}],
	}]}}}

	res := check.deny with input as inp
	res == set()
}
