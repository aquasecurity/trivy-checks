# METADATA
# title: S3 Access block should block public policy
# description: |
#   S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html
# custom:
#   id: AVD-AWS-0087
#   avd_id: AVD-AWS-0087
#   provider: aws
#   service: s3
#   severity: HIGH
#   short_code: block-public-policy
#   recommended_action: Prevent policies that allow public access being PUT
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_policy
#     good_examples: checks/cloud/aws/s3/block_public_policy.tf.go
#     bad_examples: checks/cloud/aws/s3/block_public_policy.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/s3/block_public_policy.cf.go
#     bad_examples: checks/cloud/aws/s3/block_public_policy.cf.go
package builtin.aws.s3.aws0087

import rego.v1

deny contains res if {
	some bucket in input.aws.s3.buckets
	not bucket.publicaccessblock
	res := result.new(
		"No public access block so not blocking public policies",
		bucket,
	)
}

deny contains res if {
	some bucket in input.aws.s3.buckets
	bucket.publicaccessblock
	not bucket.publicaccessblock.blockpublicpolicy.value
	res := result.new(
		"Public access block does not block public policies",
		object.get(
			bucket.publicaccessblock,
			"blockpublicpolicy",
			bucket.publicaccessblock,
		),
	)
}
