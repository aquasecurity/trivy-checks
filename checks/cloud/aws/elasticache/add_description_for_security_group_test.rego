package builtin.aws.elasticache.aws0049_test

import rego.v1

import data.builtin.aws.elasticache.aws0049 as check
import data.lib.test

test_allow_sg_with_description if {
	inp := {"aws": {"elasticache": {"securitygroups": [{"description": {"value": "sg description"}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_sg_without_description if {
	inp := {"aws": {"elasticache": {"securitygroups": [{"description": {"value": ""}}]}}}

	test.assert_equal_message("Security group does not have a description.", check.deny) with input as inp
}
