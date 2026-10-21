package builtin.aws.s3.aws0092_test

import rego.v1

import data.builtin.aws.s3.aws0092 as check
import data.lib.test

test_acl_configurations[name] if {
	some name, tc in {
		"public-read without block is denied": {
			"input": bucket_input("public-read", public_access_block(false, false)),
			"expected": 1,
		},
		"authenticated-read is reported once": {
			"input": bucket_input("authenticated-read", {}),
			"expected": 1,
		},
		"private acl is allowed": {
			"input": bucket_input("private", {}),
			"expected": 0,
		},
		"authenticated-read with blockpublicacls is allowed": {
			"input": bucket_input("authenticated-read", public_access_block(false, true)),
			"expected": 0,
		},
		"authenticated-read with ignorepublicacls is allowed": {
			"input": bucket_input("authenticated-read", public_access_block(true, false)),
			"expected": 0,
		},
		"public-read with blockpublicacls is allowed": {
			"input": bucket_input("public-read", public_access_block(false, true)),
			"expected": 0,
		},
	}

	test.assert_count(check.deny, tc.expected) with input as tc.input
}

bucket_input(acl, pab) := {"aws": {"s3": {"buckets": [object.union({"acl": {"value": acl}}, pab)]}}}

public_access_block(ignore, block) := {"publicaccessblock": {
	"ignorepublicacls": {"value": ignore},
	"blockpublicacls": {"value": block},
}}
