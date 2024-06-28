package builtin.aws.iam.aws0169_test

import rego.v1

import data.builtin.aws.iam.aws0169 as check
import data.lib.test

test_disallow_no_support_role if {
	inp := {"aws": {"iam": {"roles": [{"policies": [{
		"name": {"value": "roleName"},
		"builtin": {"value": true},
	}]}]}}}

	test.assert_equal_message("Missing IAM support role.", check.deny) with input as inp
}

test_disallow_non_built_in_support_role if {
	inp := {"aws": {"iam": {"roles": [{"policies": [{
		"name": {"value": "AWSSupportAccess"},
		"builtin": {"value": false},
	}]}]}}}

	test.assert_equal_message("Missing IAM support role.", check.deny) with input as inp
}

test_allow_has_support_role if {
	inp := {"aws": {"iam": {"roles": [{"policies": [
		{
			"name": {"value": "AWSSupplyChainFederationAdminAccess"},
			"builtin": {"value": true},
		},
		{
			"name": {"value": "AWSSupportAccess"},
			"builtin": {"value": true},
		},
	]}]}}}

	test.assert_empty(check.deny) with input as inp
}
