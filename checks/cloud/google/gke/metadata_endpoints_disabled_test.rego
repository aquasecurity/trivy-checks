package builtin.google.gke.google0048_test

import rego.v1

import data.builtin.google.gke.google0048 as check
import data.lib.test

test_deny_cluster_legacy_metadata_endpoints_enabled if {
	inp := {"google": {"gke": {"clusters": [{"nodeconfig": {"enablelegacyendpoints": {"value": true}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_cluster_legacy_metadata_endpoints_disabled if {
	inp := {"google": {"gke": {"clusters": [{"nodeconfig": {"enablelegacyendpoints": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_deny_cluster_legacy_metadata_endpoints_enabled_on_non_default_node_pool if {
	inp := {"google": {"gke": {"clusters": [{
		"removedefaultnodepool": {"value": true},
		"nodepools": [{"nodeconfig": {"enablelegacyendpoints": {"value": true}}}],
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_cluster_legacy_metadata_endpoints_disabled_on_non_default_node_pool if {
	inp := {"google": {"gke": {"clusters": [{
		"removedefaultnodepool": {"value": true},
		"nodepools": [{"nodeconfig": {"enablelegacyendpoints": {"value": false}}}],
	}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
