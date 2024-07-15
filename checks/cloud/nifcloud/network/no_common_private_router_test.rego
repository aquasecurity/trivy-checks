package builtin.nifcloud.network.nifcloud0017_test

import rego.v1

import data.builtin.nifcloud.network.nifcloud0017 as check
import data.lib.test

test_allow_with_private_lan if {
	inp := {"nifcloud": {"network": {"routers": [{"networkinterfaces": [{"networkid": {"value": "net-some-private-lan"}}]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_with_common_private_lan if {
	inp := {"nifcloud": {"network": {"routers": [{"networkinterfaces": [{"networkid": {"value": "net-COMMON_PRIVATE"}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
