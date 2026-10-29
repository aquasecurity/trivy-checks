package builtin.aws.elasticsearch.aws0126_test

import rego.v1

import data.builtin.aws.elasticsearch.aws0126 as check
import data.lib.test

test_allow_use_secure_tls_policy if {
	inp := {"aws": {"elasticsearch": {"domains": [{"endpoint": {"tlspolicy": {"value": "Policy-Min-TLS-1-2-2019-07"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_use_secure_tls_policy_2 if {
	inp := {"aws": {"elasticsearch": {"domains": [{"endpoint": {"tlspolicy": {"value": "Policy-Min-TLS-1-2-PFS-2023-10"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

# Regression: the FIPS/RFC9151 policy is secure (TLS 1.2-minimum, FIPS) and must
# not be flagged. See aquasecurity/trivy#11118.
test_allow_use_secure_tls_policy_fips if {
	inp := {"aws": {"elasticsearch": {"domains": [{"endpoint": {"tlspolicy": {"value": "Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

# A future TLS 1.3-minimum family should also be accepted without a rule edit.
test_allow_use_secure_tls_policy_tls13 if {
	inp := {"aws": {"elasticsearch": {"domains": [{"endpoint": {"tlspolicy": {"value": "Policy-Min-TLS-1-3-2025-01"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_does_not_use_secure_tls_policy if {
	inp := {"aws": {"elasticsearch": {"domains": [{"endpoint": {"tlspolicy": {"value": "Policy-Min-TLS-1-0-2019-07"}}}]}}}

	test.assert_equal_message("Domain does not have a secure TLS policy.", check.deny) with input as inp
}

# An unresolved TLS policy value must not produce a finding: the engine cannot
# determine the configured policy, so flagging it would be a false positive.
test_no_finding_for_unresolved_tls_policy if {
	inp := {"aws": {"elasticsearch": {"domains": [{"endpoint": {"tlspolicy": {"unresolvable": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
