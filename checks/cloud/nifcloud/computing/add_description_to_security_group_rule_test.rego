package builtin.nifcloud.computing.nifcloud0003_test

import rego.v1

import data.builtin.nifcloud.computing.nifcloud0003 as check
import data.lib.test

test_allow_rules_with_description if {
	inp := build_input({"ingressrules": [{"description": {"value": "test"}}]})

	res := check.deny with input as inp
	res == set()
}

test_deny_ingress_rule_without_description if {
	inp := build_input({"ingressrules": [{"description": {"value": ""}}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_egress_rule_without_description if {
	inp := build_input({"egressrules": [{"description": {"value": ""}}]})

	res := check.deny with input as inp
	count(res) == 1
}

build_input(group) := {"nifcloud": {"computing": {"securitygroups": [group]}}}
