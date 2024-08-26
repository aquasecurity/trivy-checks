package builtin.aws.redshift.aws0083_test

import rego.v1

import data.builtin.aws.redshift.aws0083 as check
import data.lib.test

test_deny_sg_without_description if {
	inp := {"aws": {"redshift": {"securitygroups": [{}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_sg_with_description if {
	inp := {"aws": {"redshift": {"securitygroups": [{"description": {"value": "some description"}}]}}}

	test.assert_empty(check.deny) with input as inp
}
