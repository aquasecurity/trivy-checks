package builtin.aws.iam.aws0144_test

import rego.v1

import data.builtin.aws.iam.aws0144 as check
import data.lib.datetime
import data.lib.test

test_allow_user_logged_in_today if {
	test.assert_empty(check.deny) with input as build_input({
		"name": "test",
		"lastaccess": {"value": time.format(time.now_ns())},
	})
}

test_allow_user_never_logged_in if {
	test.assert_empty(check.deny) with input as build_input({
		"name": {"value": "test"},
		"lastaccess": {"value": datetime.zero_time_string},
	})
}

test_disallow_user_logged_in_100_days_ago if {
	test.assert_equal_message("User has not logged in for >90 days.", check.deny) with input as build_input({
		"name": {"value": "test"},
		"lastaccess": {"value": time.format(time.now_ns() - datetime.days_to_ns(100))},
	})
}

test_disallow_user_access_key_not_used_100_days if {
	test.assert_equal_message(`User access key "AKIACKCEVSQ6C2EXAMPLE" has not been used in >90 days`, check.deny) with input as build_input({
		"name": {"value": "test"},
		"lastaccess": {"value": time.format(time.now_ns())},
		"accesskeys": [{
			"accesskeyid": {"value": "AKIACKCEVSQ6C2EXAMPLE"},
			"active": {"value": true},
			"lastaccess": {"value": time.format(time.now_ns() - datetime.days_to_ns(100))},
		}],
	})
}

test_allow_nonactive_user_access_key_not_used_100_days if {
	test.assert_empty(check.deny) with input as build_input({
		"name": "test",
		"lastaccess": {"value": time.format(time.now_ns())},
		"accesskeys": [{
			"accesskeyid": {"value": "AKIACKCEVSQ6C2EXAMPLE"},
			"active": {"value": false},
			"lastaccess": {"value": time.format(time.now_ns() - datetime.days_to_ns(100))},
		}],
	})
}

test_allow_user_access_key_used_today if {
	test.assert_empty(check.deny) with input as build_input({
		"name": "test",
		"lastaccess": {"value": time.format(time.now_ns())},
		"accesskeys": [{
			"accesskeyid": {"value": "AKIACKCEVSQ6C2EXAMPLE"},
			"active": {"value": true},
			"lastaccess": {"value": time.format(time.now_ns())},
		}],
	})
}

test_disallow_one_of_the_user_access_key_used_100_days if {
	test.assert_equal_message(`User access key "AKIACKCEVSQ6C2EXAMPLE" has not been used in >90 days`, check.deny) with input as build_input({
		"name": "test",
		"lastaccess": {"value": time.format(time.now_ns())},
		"accesskeys": [
			{
				"accesskeyid": {"value": "AKIACKCEVSQ6C2EXAMPLE"},
				"active": {"value": true},
				"lastaccess": {"value": time.format(time.now_ns())},
			},
			{
				"accesskeyid": {"value": "AKIACKCEVSQ6C2EXAMPLE"},
				"active": {"value": true},
				"lastaccess": {"value": time.format(time.now_ns() - datetime.days_to_ns(100))},
			},
		],
	})
}

build_input(body) = {"aws": {"iam": {"users": [body]}}}
