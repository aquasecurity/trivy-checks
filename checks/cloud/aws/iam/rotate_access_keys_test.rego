package builtin.aws.iam.aws0146_test

import rego.v1

import data.builtin.aws.iam.aws0146 as check
import data.lib.datetime
import data.lib.test

test_allow_access_key_created_within_90_days if {
	inp := {"aws": {"iam": {"users": [{"accesskeys": [{
		"creationdate": {"value": time.format(time.now_ns() - datetime.days_to_ns(10))},
		"accesskeyid": {"value": "keyid"},
		"active": {"value": true},
	}]}]}}}
	test.assert_empty(check.deny) with input as inp
}

test_disallow_access_key_created_more_than_90_days_ago if {
	inp := {"aws": {"iam": {"users": [{"accesskeys": [{
		"creationdate": {"value": time.format(time.now_ns() - datetime.days_to_ns(100))},
		"accesskeyid": {"value": "keyid"},
		"active": {"value": true},
	}]}]}}}
	test.assert_equal_message(`User access key "keyid" should have been rotated 10 day(s) ago`, check.deny) with input as inp
}
