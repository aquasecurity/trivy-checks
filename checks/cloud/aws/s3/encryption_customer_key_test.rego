package builtin.aws.s3.aws0132_test

import rego.v1

import data.builtin.aws.s3.aws0132 as check

test_deny_bucket_without_kms_key if {
	inp := {"aws": {"s3": {"buckets": [{"encryption": {}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_bucket_with_kms_key if {
	inp := {"aws": {"s3": {"buckets": [{"encryption": {"kmskeyid": {"value": "test"}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_log_bucket_without_kms_key if {
	inp := {"aws": {"s3": {"buckets": [{
		"encryption": {},
		"acl": {"value": "log-delivery-write"},
	}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_log_bucket_with_grant if {
	inp := {"aws": {"s3": {"buckets": [{
		"encryption": {},
		"grants": [{
			"grantee": {"uri": {"value": "http://acs.amazonaws.com/groups/s3/LogDelivery"}},
			"permissions": [{"value": "WRITE"}],
		}],
	}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_log_bucket_with_policy if {
	policyDoc := {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Service": ["logging.s3.amazonaws.com"]},
			"Action": ["s3:PutObject"],
			"Resource": "arn:aws:s3:::example-bucket/logs/*",
		}],
	}

	policyStr := json.marshal(policyDoc)

	inp := {"aws": {"s3": {"buckets": [{
		"encryption": {},
		"bucketpolicies": [{"document": {"value": policyStr}}],
	}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
