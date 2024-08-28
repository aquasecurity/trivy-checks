package builtin.aws.ec2.aws0173_test

import rego.v1

import data.builtin.aws.ec2.aws0173 as check
import data.lib.test

test_allow_default_sg_without_rules if {
	inp := build_input({"isdefault": {"value": true}})

	test.assert_empty(check.deny) with input as inp
}

test_allow_non_default_sg_with_rules if {
	inp := build_input({
		"isdefault": {"value": false},
		"egressrules": [{"cidrs": [{"value": "0.0.0.0/0"}]}],
	})

	test.assert_empty(check.deny) with input as inp
}

test_deny_default_sg_with_egress_rules if {
	inp := build_input({
		"isdefault": {"value": true},
		"egressrules": [{"cidrs": [{"value": "0.0.0.0/0"}]}],
	})

	test.assert_equal_message("Default security group for VPC has ingress or egress rules.", check.deny) with input as inp
}

test_deny_default_sg_with_ingress_rules if {
	inp := build_input({
		"isdefault": {"value": true},
		"ingressrules": [{"cidrs": [{"value": "0.0.0.0/0"}]}],
	})

	test.assert_equal_message("Default security group for VPC has ingress or egress rules.", check.deny) with input as inp
}

build_input(sg) := {"aws": {"ec2": {"vpcs": [{"securitygroups": [sg]}]}}}
