package builtin.aws.iam.aws0167_test

import rego.v1

import data.builtin.aws.iam.aws0167 as check
import data.lib.test

test_allow_one_key_is_active if {
	test.assert_empty(check.deny) with input as build_input([{"active": {"value": true}}])
}

test_allow_two_keys_but_one_non_active if {
	test.assert_empty(check.deny) with input as build_input([
		{"active": {"value": false}},
		{"active": {"value": true}},
	])
}

test_disallow_two_active_keys if {
	test.assert_equal_message("User has more than one active access key", check.deny) with input as build_input([
		{"active": {"value": true}},
		{"active": {"value": true}},
	])
}

build_input(keys) = {"aws": {"iam": {"users": [{
	"name": {"value": "test"},
	"accesskeys": keys,
}]}}}
