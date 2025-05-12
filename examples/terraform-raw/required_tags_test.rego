package user.tf.required_tags_test

import rego.v1

import data.user.tf.required_tags as check

test_allow_bucket_has_required_tags if {
	inp := {"modules": [{"blocks": [{
		"kind": "resource",
		"type": "aws_s3_bucket",
		"name": "test",
		"attributes": {"tags": {"value": {
			"Environment": "Production",
			"Project": "ProjectX",
			"Owner": "user1",
		}}},
	}]}]}

	res := check.deny with input as inp
	res == set()
}

test_deny_bucket_missing_required_tags if {
	inp := {"modules": [{"blocks": [{
		"kind": "resource",
		"type": "aws_s3_bucket",
		"name": "test",
		"attributes": {"tags": {"value": {
			"Environment": "Production",
			"Project": "ProjectX",
		}}},
	}]}]}

	res := check.deny with input as inp
	count(res) == 1
}
