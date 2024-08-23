# METADATA
# title: S3 Access block should restrict public bucket to limit access
# description: |
#   S3 buckets should restrict public policies for the bucket. By enabling, the restrict_public_buckets, only the bucket owner and AWS Services can access if it has a public policy.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html
# custom:
#   id: AVD-AWS-0093
#   avd_id: AVD-AWS-0093
#   provider: aws
#   service: s3
#   severity: HIGH
#   short_code: no-public-buckets
#   recommended_action: Limit the access to public buckets to only the owner or AWS Services (eg; CloudFront)
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#restrict_public_buckets¡
#     good_examples: checks/cloud/aws/s3/no_public_buckets.tf.go
#     bad_examples: checks/cloud/aws/s3/no_public_buckets.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/s3/no_public_buckets.cf.go
#     bad_examples: checks/cloud/aws/s3/no_public_buckets.cf.go
package builtin.aws.s3.aws0093

import rego.v1

deny contains res if {
	some bucket in input.aws.s3.buckets
	not bucket.publicaccessblock
	res := result.new(
		"No public access block so not restricting public buckets",
		bucket,
	)
}

deny contains res if {
	some bucket in input.aws.s3.buckets
	bucket.publicaccessblock
	not bucket.publicaccessblock.restrictpublicbuckets.value
	res := result.new(
		"Public access block does not restrict public buckets",
		object.get(
			bucket.publicaccessblock,
			"restrictpublicbuckets",
			bucket.publicaccessblock,
		),
	)
}
