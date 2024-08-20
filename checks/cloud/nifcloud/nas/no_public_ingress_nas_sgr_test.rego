package builtin.nifcloud.nas.nifcloud0014_test

import rego.v1

import data.builtin.nifcloud.nas.nifcloud0014 as check
import data.lib.test

test_deny_ingress_sg_rule_with_wildcard_address if {
	inp := {"nifcloud": {"nas": {"nassecuritygroups": [{"cidrs": [{"value": "0.0.0.0/0"}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_ingress_sg_rule_with_private_address if {
	inp := {"nifcloud": {"nas": {"nassecuritygroups": [{"cidrs": [{"value": "10.0.0.0/16"}]}]}}}

	res := check.deny with input as inp
	res == set()
}
