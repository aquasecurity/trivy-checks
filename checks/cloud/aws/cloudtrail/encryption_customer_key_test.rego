package builtin.aws.cloudtrail.aws0015_test

import rego.v1

import data.builtin.aws.cloudtrail.aws0015 as check
import data.lib.test

test_allow_trail_with_cmk if {
	inp := {"aws": {"cloudtrail": {"trails": [{"kmskeyid": {"value": "key-id"}}]}}}
	test.assert_empty(check.deny) with input as inp
}

test_disallow_trail_without_cmk if {
	inp := {"aws": {"cloudtrail": {"trails": [{"kmskeyid": {"value": ""}}]}}}
	test.assert_equal_message("CloudTrail does not use a customer managed key to encrypt the logs.", check.deny) with input as inp
}
