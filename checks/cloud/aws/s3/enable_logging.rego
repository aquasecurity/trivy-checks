# METADATA
# title: S3 Bucket Logging
# description: Ensures S3 bucket logging is enabled for S3 buckets
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html
# - https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html
# custom:
#   id: AVD-AWS-0089
#   avd_id: AVD-AWS-0089
#   provider: aws
#   service: s3
#   severity: LOW
#   short_code: enable-logging
#   aliases:
#   - s3-bucket-logging
#   recommended_action: Add a logging block to the resource to enable access logging
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: s3
#           provider: aws
#   terraform:
#     good_examples: checks/cloud/aws/s3/enable_bucket_logging.yaml
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket
#   cloud_formation:
#     good_examples: checks/cloud/aws/s3/enable_bucket_logging.yaml
package builtin.aws.s3.aws0089

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	bucket := input.aws.s3.buckets[_]
	not bucket_has_server_logging_access(bucket)
	not is_logging_enabled(bucket)
	res := result.new(
		"Bucket has logging disabled",
		metadata.obj_by_path(bucket, ["logging", "enabled"]),
	)
}

is_logging_enabled(bucket) if bucket.logging.enabled.value

# Canned ACL
# The LogDelivery group gets WRITE and READ_ACP permissions on the bucket.
bucket_has_server_logging_access(bucket) if {
	bucket.acl.value == "log-delivery-write"
}

bucket_has_server_logging_access(bucket) if {
	some grant in bucket.grants
	grantee_is_log_delivery_group(grant)
	has_write_and_read_acp_permissions(grant.permissions)
}

# Grant permissions to the log delivery group by using a bucket AC
has_write_and_read_acp_permissions(permissions) if {
	has_permission(permissions, "FULL_CONTROL")
}

has_write_and_read_acp_permissions(permissions) if {
	has_permission(permissions, "WRITE")
	has_permission(permissions, "READ_ACP")
}

has_permission(permissions, v) if {
	some permission in permissions
	permission.value == v
}

log_group := "http://acs.amazonaws.com/groups/s3/LogDelivery"

grantee_is_log_delivery_group(grant) if grant.grantee.uri.value == log_group

# Grant permissions to the logging service principal by using a bucket policy
bucket_has_server_logging_access(bucket) if {
	policy := bucket.bucketpolicies[_]
	doc := json.unmarshal(policy.document.value)
	statement := doc.Statement[_]
	statement.Effect == "Allow"
	"s3:PutObject" in statement.Action
	"logging.s3.amazonaws.com" in statement.Principal.Service
}
