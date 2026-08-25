package builtin.aws.elb.aws0047_test

import rego.v1

import data.builtin.aws.elb.aws0047 as check
import data.lib.test

test_deny_with_outdated_tls_policies if {
	policies := {
		"ELBSecurityPolicy-TLS13-1-0-FIPS-2023-04",
		"ELBSecurityPolicy-TLS13-1-0-FIPS-PQ-2025-09",
		"ELBSecurityPolicy-TLS13-1-0-PQ-2025-09",
		"ELBSecurityPolicy-TLS13-1-1-FIPS-2023-04",
	}

	every policy in policies {
		inp := {"aws": {"elb": {"loadbalancers": [{"listeners": [{"tlspolicy": {"value": policy}}]}]}}}
		test.assert_equal_message("Listener uses an outdated TLS policy.", check.deny) with input as inp
	}
}

test_allow_not_managed if {
	inp := {"aws": {"elb": {"loadbalancers": [{
		"__defsec_metadata": {"managed": false},
		"listeners": [{"tlspolicy": {"value": "ELBSecurityPolicy-TLS13-1-0-FIPS-2023-04"}}],
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_with_secure_tls_policies if {
	policies := {
		"ELBSecurityPolicy-TLS-1-2-2017-01",
		"ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
		"ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
	}

	every policy in policies {
		inp := {"aws": {"elb": {"loadbalancers": [{"listeners": [{"tlspolicy": {"value": policy}}]}]}}}
		test.assert_empty(check.deny) with input as inp
	}
}
