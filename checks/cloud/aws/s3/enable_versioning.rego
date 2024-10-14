# METADATA
# title: S3 Data should be versioned
# description: |
#   Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket.
#
#   You can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets.
#
#   With versioning you can recover more easily from both unintended user actions and application failures.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
# custom:
#   id: AVD-AWS-0090
#   avd_id: AVD-AWS-0090
#   provider: aws
#   service: s3
#   severity: MEDIUM
#   short_code: enable-versioning
#   recommended_action: Enable versioning to protect against accidental/malicious removal or modification
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning
#     good_examples: checks/cloud/aws/s3/enable_versioning.yaml
#     bad_examples: checks/cloud/aws/s3/enable_versioning.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/s3/enable_versioning.yaml
#     bad_examples: checks/cloud/aws/s3/enable_versioning.yaml
package builtin.aws.s3.aws0090

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some bucket in input.aws.s3.buckets
	not bucket.versioning.enabled.value
	res := result.new(
		"Bucket does not have versioning enabled",
		metadata.obj_by_path(bucket, ["versioning", "enabled"]),
	)
}
