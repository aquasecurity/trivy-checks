package builtin.aws.ecr.aws0030_test

import rego.v1

import data.builtin.aws.ecr.aws0030 as check
import data.lib.test

test_allow_image_scanning_enabled if {
	inp := {"aws": {"ecr": {"repositories": [{"imagescanning": {"scanonpush": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_image_scanning_disabled if {
	inp := {"aws": {"ecr": {"repositories": [{"imagescanning": {"scanonpush": {"value": false}}}]}}}

	test.assert_equal_message("Image scanning is not enabled", check.deny) with input as inp
}
