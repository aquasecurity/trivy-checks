package builtin.nifcloud.network.nifcloud0019_test

import rego.v1

import data.builtin.nifcloud.network.nifcloud0019 as check
import data.lib.test

test_allow_elb_with_private_lan if {
	inp := {"nifcloud": {"network": {"elasticloadbalancers": [{"networkinterfaces": [{"networkid": {"value": "net-some-private-lan"}}]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_elb_with_common_private_lan if {
	inp := {"nifcloud": {"network": {"elasticloadbalancers": [{"networkinterfaces": [{"networkid": {"value": "net-COMMON_PRIVATE"}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
