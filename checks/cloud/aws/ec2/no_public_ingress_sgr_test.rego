package builtin.aws.ec2.aws0107_test

import rego.v1

import data.builtin.aws.ec2.aws0107 as check
import data.lib.test

test_deny_ingress_sq_with_wildcard_address if {
	inp := {"aws": {"ec2": {"securitygroups": [{"ingressrules": [{"cidrs": [{"value": "0.0.0.0/0"}]}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_ingress_sg_with_private_address if {
	inp := {"aws": {"ec2": {"securitygroups": [{"ingressrules": [{"cidrs": [{"value": "10.0.0.0/16"}]}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
