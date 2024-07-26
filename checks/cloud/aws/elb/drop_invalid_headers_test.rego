package builtin.aws.elb.aws0052_test

import rego.v1

import data.builtin.aws.elb.aws0052 as check
import data.lib.test

test_allow_drop_invalid_headers if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"type": {"value": "application"},
		"dropinvalidheaderfields": {"value": true},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_without_drop_invalid_headers_but_no_application if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"type": {"value": "gateway"},
		"dropinvalidheaderfields": {"value": false},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_without_drop_invalid_headers_and_application if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"type": {"value": "application"},
		"dropinvalidheaderfields": {"value": false},
	}]}}}

	test.assert_equal_message("Application load balancer is not set to drop invalid headers.", check.deny) with input as inp
}
