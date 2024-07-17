package builtin.google.gke.google0062_test

import rego.v1

import data.builtin.google.gke.google0062 as check
import data.lib.test

test_deny_legacy_abac_enabled if {
	inp := {"google": {"gke": {"clusters": [{"enablelegacyabac": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_legacy_abac_disabled if {
	inp := {"google": {"gke": {"clusters": [{"enablelegacyabac": {"value": false}}]}}}

	res := check.deny with input as inp
	res == set()
}
