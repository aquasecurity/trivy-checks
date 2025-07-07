# METADATA
# title: S3 encryption should use Customer Managed Keys
# description: |
#   Encryption using AWS keys provides protection for your S3 buckets. To gain greater control over encryption, such as key rotation, access policies, and auditability, use customer managed keys (CMKs) with SSE-KMS.
#   Note that SSE-KMS is not supported for S3 server access logging destination buckets; in such cases, use SSE-S3 instead.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html
# custom:
#   id: AWS-0132
#   aliases:
#     - AVD-AWS-0132
#     - encryption-customer-key
#   long_id: aws-s3-encryption-customer-key
#   provider: aws
#   service: s3
#   severity: HIGH
#   recommended_action: Use SSE-KMS with a customer managed key (CMK)
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   examples: checks/cloud/aws/s3/encryption_customer_key.yaml
package builtin.aws.s3.aws0132

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some bucket in input.aws.s3.buckets

	# Log buckets don't support non AES256 encryption - this rule doesn't apply here
	# https://aws.amazon.com/premiumsupport/knowledge-center/s3-server-access-log-not-delivered/
	not log_bucket(bucket)

	without_cmk(bucket)

	res := result.new(
		"Bucket does not encrypt data with a customer managed key.",
		object.get(bucket, "encryption", bucket),
	)
}

# The LogDelivery group gets WRITE and READ_ACP permissions on the bucket
log_bucket(bucket) if lower(bucket.acl.value) == "log-delivery-write"

# https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html#grant-log-delivery-permissions-acl
log_bucket(bucket) if {
	some grant in bucket.grants
	grant.grantee.uri.value == "http://acs.amazonaws.com/groups/s3/LogDelivery"
	some permission in grant.permissions
	permission.value in {"WRITE", "FULL_CONTROL"}
}

# https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html#grant-log-delivery-permissions-bucket-policy
log_bucket(bucket) if {
	some policy in bucket.bucketpolicies
	doc := json.unmarshal(policy.document.value)
	some statement in doc.Statement
	lower(statement.Effect) == "allow"
	"logging.s3.amazonaws.com" in statement.Principal.Service
	some action in statement.Action
	lower(action) == "s3:putobject"
}

without_cmk(bucket) if value.is_empty(bucket.encryption.kmskeyid)

without_cmk(bucket) if not bucket.encryption.kmskeyid
