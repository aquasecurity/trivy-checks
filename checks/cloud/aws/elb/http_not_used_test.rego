package builtin.aws.elb.aws0054_test

import rego.v1

import data.builtin.aws.elb.aws0054 as check
import data.lib.test

test_allow_https if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"type": {"value": "application"},
		"listeners": [{"protocol": {"value": "HTTPS"}}],
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_http_with_redirect if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"type": {"value": "application"},
		"listeners": [{
			"protocol": {"value": "HTTP"},
			"defaultactions": [{"type": {"value": "redirect"}}],
		}],
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_http_mixed_actions if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"type": {"value": "application"},
		"listeners": [{
			"protocol": {"value": "HTTP"},
			"defaultactions": [
				{"type": {"value": "redirect"}},
				{"type": {"value": "forward"}},
			],
		}],
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_http_but_not_application if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"type": {"value": "network"},
		"listeners": [{"protocol": {"value": "HTTP"}}],
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_http_without_redirect if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"type": {"value": "application"},
		"listeners": [{
			"protocol": {"value": "HTTP"},
			"defaultactions": [{"type": {"value": "forward"}}],
		}],
	}]}}}

	test.assert_equal_message("Listener for application load balancer does not use HTTPS.", check.deny) with input as inp
}
