# METADATA
# title: S3 Access block should block public ACL
# description: |
#   S3 buckets should block public ACLs on buckets and any objects they contain. By blocking, PUTs with fail if the object has any public ACL a.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
# custom:
#   id: AVD-AWS-0086
#   avd_id: AVD-AWS-0086
#   provider: aws
#   service: s3
#   severity: HIGH
#   short_code: block-public-acls
#   recommended_action: Enable blocking any PUT calls with a public ACL specified
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#block_public_acls
#     good_examples: checks/cloud/aws/s3/block_public_acls.tf.go
#     bad_examples: checks/cloud/aws/s3/block_public_acls.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/s3/block_public_acls.cf.go
#     bad_examples: checks/cloud/aws/s3/block_public_acls.cf.go
package builtin.aws.s3.aws0086

import rego.v1

deny contains res if {
	some bucket in input.aws.s3.buckets
	not bucket.publicaccessblock
	res := result.new(
		"No public access block so not blocking public acls",
		bucket,
	)
}

deny contains res if {
	some bucket in input.aws.s3.buckets
	bucket.publicaccessblock
	not bucket.publicaccessblock.blockpublicacls.value
	res := result.new(
		"Public access block does not block public ACLs",
		object.get(
			bucket.publicaccessblock,
			"blockpublicacls",
			bucket.publicaccessblock,
		),
	)
}
