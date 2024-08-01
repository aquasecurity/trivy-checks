package builtin.aws.s3.aws0089

test_deny_logging_disabled {
	r := deny with input as {"aws": {"s3": {"buckets": [{"logging": {"enabled": {"value": false}}}]}}}
	count(r) == 1
}

test_allow_logging_enabled {
	r := deny with input as {"aws": {"s3": {"buckets": [{"logging": {"enabled": {"value": true}}}]}}}
	count(r) == 0
}

test_allow_logging_disabled_but_bucket_has_server_logging_access_acl {
	r := deny with input as {"aws": {"s3": {"buckets": [{
		"logging": {"enabled": {"value": false}},
		"acl": {"value": "log-delivery-write"},
	}]}}}
	count(r) == 0
}

test_deny_logging_disabled_and_bucket_does_not_have_server_access_logging {
	r := deny with input as {"aws": {"s3": {"buckets": [{
		"logging": {"enabled": {"value": false}},
		"acl": {"value": "private"},
	}]}}}
	count(r) == 1
}

test_allow_logging_disabled_but_bucket_has_server_logging_access_grant {
	r := deny with input as {"aws": {"s3": {"buckets": [{
		"logging": {"enabled": {"value": false}},
		"acl": {"value": "log-delivery-write"},
		"grants": [
			{
				"grantee": {
					"id": {"value": "111122223333"},
					"type": {"value": "CanonicalUser"},
				},
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

test_allow_logging_disabled_but_bucket_has_server_logging_access_policy {
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
