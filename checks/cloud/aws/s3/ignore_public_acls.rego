# METADATA
# title: S3 Access Block should Ignore Public Acl
# description: |
#   S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
# custom:
#   id: AVD-AWS-0091
#   avd_id: AVD-AWS-0091
#   provider: aws
#   service: s3
#   severity: HIGH
#   short_code: ignore-public-acls
#   recommended_action: Enable ignoring the application of public ACLs in PUT calls
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#ignore_public_acls
#     good_examples: checks/cloud/aws/s3/ignore_public_acls.tf.go
#     bad_examples: checks/cloud/aws/s3/ignore_public_acls.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/s3/ignore_public_acls.cf.go
#     bad_examples: checks/cloud/aws/s3/ignore_public_acls.cf.go
package builtin.aws.s3.aws0091

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
	not bucket.publicaccessblock.ignorepublicacls.value
	res := result.new(
		"Public access block does not ignore public ACLs",
		object.get(
			bucket.publicaccessblock,
			"ignorepublicacls",
			bucket.publicaccessblock,
		),
	)
}
