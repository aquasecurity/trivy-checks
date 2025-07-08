# METADATA
# title: S3 Buckets not publicly accessible through ACL.
# description: |
#   Buckets should not have ACLs that allow public access
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
# custom:
#   id: AWS-0092
#   aliases:
#     - AVD-AWS-0092
#     - no-public-access-with-acl
#   long_id: aws-s3-no-public-access-with-acl
#   provider: aws
#   service: s3
#   severity: HIGH
#   recommended_action: Don't use canned ACLs or switch to private acl
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   examples: checks/cloud/aws/s3/no_public_access_with_acl.yaml
package builtin.aws.s3.aws0092

import rego.v1

import data.lib.aws.s3

deny contains res if {
	some bucket in input.aws.s3.buckets
	s3.bucket_has_public_exposure_acl(bucket)
	bucket.acl.value == "authenticated-read"
	res := result.new(
		"Bucket is exposed to all AWS accounts via ACL.",
		bucket.acl,
	)
}

deny contains res if {
	some bucket in input.aws.s3.buckets
	s3.bucket_has_public_exposure_acl(bucket)
	bucket.acl.value != "authenticated-read"

	# TODO: check private?
	res := result.new(
		sprintf("Bucket has a public ACL: %q", [bucket.acl.value]),
		bucket.acl,
	)
}
