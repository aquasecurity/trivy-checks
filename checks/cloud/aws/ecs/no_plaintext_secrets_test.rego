package builtin.aws.ecs.aws0036_test

import rego.v1

import data.builtin.aws.ecs.aws0036 as check
import data.lib.test

test_deny_definiton_with_plaintext_sensitive_information if {
	inp := {"aws": {"ecs": {"taskdefinitions": [{"containerdefinitions": [{"environment": [
		{
			"name": "ENVIRONMENT",
			"value": "development",
		},
		{
			"name": "DATABASE_PASSWORD",
			"value": "password123",
		},
	]}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_task_without_sensitive_information if {
	inp := {"aws": {"ecs": {"taskdefinitions": [{"containerdefinitions": [{"environment": [{
		"Name": "ENVIRONMENT",
		"Value": "development",
	}]}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
