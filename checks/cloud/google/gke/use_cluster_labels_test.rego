package builtin.google.gke.google0051_test

import rego.v1

import data.builtin.google.gke.google0051 as check
import data.lib.test

test_deny_cluster_does_not_use_labels if {
	inp := {"google": {"gke": {"clusters": [{"resourcelabels": {"value": {}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_cluser_uses_labels if {
	inp := {"google": {"gke": {"clusters": [{"resourcelabels": {"value": {"env": "staging"}}}]}}}

	res := check.deny with input as inp
	res == set()
}
