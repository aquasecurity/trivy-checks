package builtin.aws.redshift.aws0085_test

import rego.v1

import data.builtin.aws.redshift.aws0085 as check
import data.lib.test

test_deny_security_groups_present if {
	inp := {"aws": {"redshift": {"securitygroups": [{}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_no_security_groups if {
	inp := {"aws": {"redshift": {}}}

	test.assert_empty(check.deny) with input as inp
}
