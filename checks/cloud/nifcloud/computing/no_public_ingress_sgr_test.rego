package builtin.nifcloud.computing.nifcloud0001_test

import rego.v1

import data.builtin.nifcloud.computing.nifcloud0001 as check
import data.lib.test

test_deny_ingress_sg_rule_with_wildcard_address if {
	inp := {"nifcloud": {"computing": {"securitygroups": [{"ingressrules": [{"cidr": {"value": "0.0.0.0/0"}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_ingress_sg_rule_with_private_address if {
	inp := {"nifcloud": {"computing": {"securitygroups": [{"ingressrules": [{"cidr": {"value": "10.0.0.0/16"}}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
