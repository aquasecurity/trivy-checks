package builtin.aws.cloudtrail.aws0014_test

import rego.v1

import data.builtin.aws.cloudtrail.aws0014 as check
import data.lib.test

test_disallow_cloudtrail_without_all_regions if {
	r := check.deny with input as {"aws": {"cloudtrail": {"trails": [{"ismultiregion": {"value": false}}]}}}
	test.assert_equal_message("CloudTrail is not enabled across all regions.", r)
}

test_allow_cloudtrail_with_all_regions if {
	r := check.deny with input as {"aws": {"cloudtrail": {"trails": [{"ismultiregion": {"value": true}}]}}}
	test.assert_empty(r)
}
