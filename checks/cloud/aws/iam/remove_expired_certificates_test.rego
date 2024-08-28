package builtin.aws.iam.aws0168_test

import rego.v1

import data.builtin.aws.iam.aws0168 as check
import data.lib.datetime
import data.lib.test

test_disallow_expired_certificate if {
	inp := {"aws": {"iam": {"servercertificates": [{"expiration": {"value": time.format(time.now_ns() - datetime.days_to_ns(10))}}]}}}

	test.assert_equal_message("Certificate has expired", check.deny) with input as inp
}

test_allow_non_expired_certificate if {
	inp := {"aws": {"iam": {"servercertificates": [{"expiration": {"value": time.format(time.now_ns() + datetime.days_to_ns(10))}}]}}}

	test.assert_empty(check.deny) with input as inp
}
