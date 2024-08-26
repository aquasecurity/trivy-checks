package builtin.aws.elb.aws0053_test

import rego.v1

import data.builtin.aws.elb.aws0053 as check
import data.lib.test

test_deny_public_alb if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"type": {"value": "application"},
		"internal": {"value": false},
	}]}}}

	test.assert_equal_message("Load balancer is exposed publicly.", check.deny) with input as inp
}

test_allow_public_but_gateway if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"type": {"value": "gateway"},
		"internal": {"value": false},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_internal if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"type": {"value": "application"},
		"internal": {"value": true},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}
