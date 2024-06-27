package builtin.aws.elasticsearch.aws0126_test

import rego.v1

import data.builtin.aws.elasticsearch.aws0126 as check
import data.lib.test

test_allow_use_secure_tls_policy if {
	inp := {"aws": {"elasticsearch": {"domains": [{"endpoint": {"tlspolicy": {"value": "Policy-Min-TLS-1-2-2019-07"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_does_not_use_secure_tls_policy if {
	inp := {"aws": {"elasticsearch": {"domains": [{"endpoint": {"tlspolicy": {"value": "Policy-Min-TLS-1-0-2019-07"}}}]}}}

	test.assert_equal_message("Domain does not have a secure TLS policy.", check.deny) with input as inp
}
