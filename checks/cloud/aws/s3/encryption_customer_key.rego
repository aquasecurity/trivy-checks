# METADATA
# title: S3 encryption should use Customer Managed Keys
# description: |
#   Encryption using AWS keys provides protection for your S3 buckets. To increase control of the encryption and manage factors like rotation use customer managed keys.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html
# custom:
#   id: AVD-AWS-0132
#   avd_id: AVD-AWS-0132
#   provider: aws
#   service: s3
#   severity: HIGH
#   short_code: encryption-customer-key
#   recommended_action: Enable encryption using customer managed keys
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#enable-default-server-side-encryption
#     good_examples: checks/cloud/aws/s3/encryption_customer_key.yaml
#     bad_examples: checks/cloud/aws/s3/encryption_customer_key.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/s3/encryption_customer_key.yaml
#     bad_examples: checks/cloud/aws/s3/encryption_customer_key.yaml
package builtin.aws.s3.aws0132

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some bucket in input.aws.s3.buckets

	# Log buckets don't support non AES256 encryption - this rule doesn't apply here
	# https://aws.amazon.com/premiumsupport/knowledge-center/s3-server-access-log-not-delivered/
	non_log_bucket(bucket)

	without_cmk(bucket)

	res := result.new(
		"Bucket does not encrypt data with a customer managed key.",
		object.get(bucket, "encryption", bucket),
	)
}

non_log_bucket(bucket) if {
	not value.is_unresolvable(bucket.acl)
	lower(bucket.acl.value) != "log-delivery-write"
}

non_log_bucket(bucket) if not bucket.acl

without_cmk(bucket) if value.is_empty(bucket.encryption.kmskeyid)

without_cmk(bucket) if not bucket.encryption.kmskeyid
