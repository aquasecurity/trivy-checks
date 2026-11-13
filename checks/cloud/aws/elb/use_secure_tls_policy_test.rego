package builtin.aws.elb.aws0047_test

import rego.v1

import data.builtin.aws.elb.aws0047 as check
import data.lib.test

test_deny_with_outdated_tls_policy if {
	inp := {"aws": {"elb": {"loadbalancers": [{"listeners": [{"tlspolicy": {"value": "ELBSecurityPolicy-TLS-1-0-2015-04"}}]}]}}}

	test.assert_equal_message("Listener uses an outdated TLS policy.", check.deny) with input as inp
}

test_allow_not_managed if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"__defsec_metadata": {"managed": false},
		"listeners": [{"tlspolicy": {"value": "ELBSecurityPolicy-TLS-1-0-2015-04"}}],
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_with_actual_tls_policy if {
	inp := {"aws": {"elb": {"loadbalancers": [{"listeners": [{"tlspolicy": {"value": "ELBSecurityPolicy-TLS-1-2-2017-01"}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_with_fips_policy_allowing_tls_1_0 if {
	inp := {"aws": {"elb": {"loadbalancers": [{"listeners": [{"tlspolicy": {"value": "ELBSecurityPolicy-TLS13-1-0-FIPS-2023-04"}}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_with_unknown_tls_policy if {
	inp := {"aws": {"elb": {"loadbalancers": [{"listeners": [{"tlspolicy": {"value": "ELBSecurityPolicy-Unknown"}}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_with_ext1_tls_policy if {
	inp := {"aws": {"elb": {"loadbalancers": [{"listeners": [{"tlspolicy": {"value": "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06"}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_without_tls_policy if {
	inp := {"aws": {"elb": {"loadbalancers": [{"listeners": [{"tlspolicy": {"value": ""}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_with_unresolvable_tls_policy if {
	inp := {"aws": {"elb": {"loadbalancers": [{"listeners": [{"tlspolicy": {"value": "", "unresolvable": true}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
