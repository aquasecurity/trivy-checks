package builtin.aws.s3.aws0089

import rego.v1

test_deny_logging_disabled if {
	r := deny with input as {"aws": {"s3": {"buckets": [{"logging": {"enabled": {"value": false}}}]}}}
	count(r) == 1
}

test_allow_logging_enabled if {
	r := deny with input as {"aws": {"s3": {"buckets": [{"logging": {"enabled": {"value": true}}}]}}}
	count(r) == 0
}

test_allow_logging_disabled_but_bucket_has_server_logging_access_acl if {
	r := deny with input as {"aws": {"s3": {"buckets": [{
		"logging": {"enabled": {"value": false}},
		"acl": {"value": "log-delivery-write"},
	}]}}}
	count(r) == 0
}

test_deny_logging_disabled_and_bucket_does_not_have_server_access_logging if {
	r := deny with input as {"aws": {"s3": {"buckets": [{
		"logging": {"enabled": {"value": false}},
		"acl": {"value": "private"},
	}]}}}
	count(r) == 1
}

test_allow_logging_disabled_but_bucket_has_server_logging_access_grant if {
	r := deny with input as {"aws": {"s3": {"buckets": [{
		"logging": {"enabled": {"value": false}},
		"acl": {"value": "log-delivery-write"},
		"grants": [
			{
				"grantee": {"type": {"value": "CanonicalUser"}},
				"permissions": [{"value": "FULL_CONTROL"}],
			},
			{
				"grantee": {
					"uri": {"value": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
					"type": {"value": "GROUP"},
				},
				"permissions": [
					{"value": "READ_ACP"},
					{"value": "WRITE"},
				],
			},
		],
	}]}}}
	count(r) == 0
}

test_allow_logging_disabled_but_bucket_has_server_logging_access_policy if {
	r := deny with input as {"aws": {"s3": {"buckets": [{
		"logging": {"enabled": {"value": false}},
		"bucketpolicies": [{"document": {"value": json.marshal({
			"Version": "2012-10-17",
			"Statement": [{
				"Sid": "S3ServerAccessLogsPolicy",
				"Effect": "Allow",
				"Principal": {"Service": ["logging.s3.amazonaws.com"]},
				"Action": ["s3:PutObject"],
				"Resource": "arn:aws:s3:::DOC-EXAMPLE-DESTINATION-BUCKET-logs/*",
			}],
		})}}],
	}]}}}
	count(r) == 0
}
