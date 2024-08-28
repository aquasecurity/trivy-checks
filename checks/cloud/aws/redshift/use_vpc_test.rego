package builtin.aws.redshift.aws0127_test

import rego.v1

import data.builtin.aws.redshift.aws0127 as check
import data.lib.test

test_deny_missing_subnet_name if {
	inp := {"aws": {"redshift": {"clusters": [{"subnetgroupname": {"value": ""}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_with_subnet_name if {
	inp := {"aws": {"redshift": {"clusters": [{"subnetgroupname": {"value": "foo"}}]}}}

	test.assert_empty(check.deny) with input as inp
}
