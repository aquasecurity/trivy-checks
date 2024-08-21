package builtin.aws.ecr.aws0031_test

import rego.v1

import data.builtin.aws.ecr.aws0031 as check
import data.lib.test

test_allow_immutable_repository if {
	inp := {"aws": {"ecr": {"repositories": [{"imagetagsimmutable": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_immutable_repository if {
	inp := {"aws": {"ecr": {"repositories": [{"imagetagsimmutable": {"value": false}}]}}}

	test.assert_equal_message("Repository tags are mutable.", check.deny) with input as inp
}
