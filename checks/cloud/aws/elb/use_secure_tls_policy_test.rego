package builtin.aws.elb.aws0047_test

import rego.v1

import data.builtin.aws.elb.aws0047 as check
import data.lib.test

test_deny_with_outdated_tls_policy if {
	inp := {"aws": {"elb": {"loadbalancers": [{"listeners": [{"tlspolicy": {"value": "ELBSecurityPolicy-TLS-1-0-2015-04"}}]}]}}}

	test.assert_equal_message("Load balancer listener using TLS v1.0", check.deny) with input as inp
}

test_allow_with_actual_tls_policy if {
	inp := {"aws": {"elb": {"loadbalancers": [{"listeners": [{"tlspolicy": {"value": "ELBSecurityPolicy-TLS-1-2-2017-01"}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
