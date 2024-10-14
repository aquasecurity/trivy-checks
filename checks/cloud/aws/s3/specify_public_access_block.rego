# METADATA
# title: S3 buckets should each define an aws_s3_bucket_public_access_block
# description: |
#   The "block public access" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central types for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
# custom:
#   id: AVD-AWS-0094
#   avd_id: AVD-AWS-0094
#   provider: aws
#   service: s3
#   severity: LOW
#   short_code: specify-public-access-block
#   recommended_action: Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#bucket
#     good_examples: checks/cloud/aws/s3/specify_public_access_block.yaml
#     bad_examples: checks/cloud/aws/s3/specify_public_access_block.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/s3/specify_public_access_block.yaml
#     bad_examples: checks/cloud/aws/s3/specify_public_access_block.yaml
package builtin.aws.s3.aws0094

import rego.v1

deny contains res if {
	some bucket in input.aws.s3.buckets
	not bucket.publicaccessblock
	res := result.new(
		"Bucket does not have a corresponding public access block.",
		bucket,
	)
}
