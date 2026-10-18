package builtin.aws.s3.aws0092_test

import rego.v1

import data.builtin.aws.s3.aws0092 as check

test_deny_public_acl if {
	inp := {"aws": {"s3": {"buckets": [{
		"acl": {"value": "public-read"},
		"publicaccessblock": {
			"ignorepublicacls": {"value": false},
			"blockpublicacls": {"value": false},
		},
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_private_acl if {
	inp := {"aws": {"s3": {"buckets": [{"acl": {"value": "private"}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_deny_authenticated_read_reported_once if {
	inp := {"aws": {"s3": {"buckets": [{"acl": {"value": "authenticated-read"}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_authenticated_read_with_public_access_block if {
	inp := {"aws": {"s3": {"buckets": [{
		"acl": {"value": "authenticated-read"},
		"publicaccessblock": {
			"ignorepublicacls": {"value": false},
			"blockpublicacls": {"value": true},
		},
	}]}}}
	res := check.deny with input as inp
	count(res) == 0
}

test_allow_public_read_with_public_access_block if {
	inp := {"aws": {"s3": {"buckets": [{
		"acl": {"value": "public-read"},
		"publicaccessblock": {
			"ignorepublicacls": {"value": false},
			"blockpublicacls": {"value": true},
		},
	}]}}}
	res := check.deny with input as inp
	count(res) == 0
}
