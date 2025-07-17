# METADATA
# title: Unencrypted S3 bucket.
# description: |
#   S3 Buckets should be encrypted to protect the data that is stored within them if access is compromised.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html
# custom:
#   id: AVD-AWS-0088
#   avd_id: AVD-AWS-0088
#   provider: aws
#   service: s3
#   severity: HIGH
#   short_code: enable-bucket-encryption
#   recommended_action: Configure bucket encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   examples: checks/cloud/aws/s3/enable_bucket_encryption.yaml
package builtin.aws.s3.aws0088

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some bucket in input.aws.s3.buckets
	not bucket.encryption.enabled.value
	res := result.new(
		"Bucket does not have encryption enabled",
		metadata.obj_by_path(bucket, ["encryption", "enabled"]),
	)
}
