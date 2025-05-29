package builtin.google.gke.google0057_test

import rego.v1

import data.builtin.google.gke.google0057 as check

test_node_metadata_configurations[name] if {
	some name, tc in {
		"cluster node config exposes metadata by default": {
			"input": {"google": {"gke": {"clusters": [{"nodeconfig": {"workloadmetadataconfig": {"nodemetadata": {"value": "UNSPECIFIED"}}}}]}}},
			"expected": 1,
		},
		"node pool config exposes metadata": {
			"input": {"google": {"gke": {"clusters": [{"nodepools": [{"nodeconfig": {"workloadmetadataconfig": {"nodemetadata": {"value": "UNSPECIFIED"}}}}]}]}}},
			"expected": 1,
		},
		"metadata exposure is secure": {
			"input": {"google": {"gke": {"clusters": [{
				"nodeconfig": {"workloadmetadataconfig": {"nodemetadata": {"value": "SECURE"}}},
				"nodepools": [{"nodeconfig": {"workloadmetadataconfig": {"nodemetadata": {"value": "SECURE"}}}}],
			}]}}},
			"expected": 0,
		},
		"cluster node config uses GCE_METADATA": {
			"input": {"google": {"gke": {"clusters": [{"nodeconfig": {"workloadmetadataconfig": {"nodemetadata": {"value": "GCE_METADATA"}}}}]}}},
			"expected": 1,
		},
	}

	res := check.deny with input as tc.input
	count(res) == tc.expected
}
