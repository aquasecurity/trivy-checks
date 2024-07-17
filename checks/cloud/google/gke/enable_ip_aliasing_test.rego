package builtin.google.gke.google0049_test

import rego.v1

import data.builtin.google.gke.google0049 as check
import data.lib.test

test_deny_ip_aliasing_disabled if {
	inp := {"google": {"gke": {"clusters": [{"ipallocationpolicy": {"enabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_ip_aliasing_enabled if {
	inp := {"google": {"gke": {"clusters": [{"ipallocationpolicy": {"enabled": {"value": true}}}]}}}

	res := check.deny with input as inp
	res == set()
}
