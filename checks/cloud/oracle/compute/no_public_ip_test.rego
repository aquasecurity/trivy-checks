package builtin.oracle.compute.oracle0001_test

import rego.v1

import data.builtin.oracle.compute.oracle0001 as check
import data.lib.test

test_deny_pool_is_public if {
	inp := {"oracle": {"compute": {"addressreservations": [{"pool": {"value": "public-ippool"}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_pool_is_cloud if {
	inp := {"oracle": {"compute": {"addressreservations": [{"pool": {"value": "cloud-ippool"}}]}}}

	res := check.deny with input as inp
	res == set()
}
