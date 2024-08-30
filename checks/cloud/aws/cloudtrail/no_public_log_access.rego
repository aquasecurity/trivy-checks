# METADATA
# title: The S3 Bucket backing Cloudtrail should be private
# description: |
#   CloudTrail logs will be publicly exposed, potentially containing sensitive information. CloudTrail logs a record of every API call made in your account. These log files are stored in an S3 bucket. CIS recommends that the S3 bucket policy, or access control list (ACL), applied to the S3 bucket that CloudTrail logs to prevents public access to the CloudTrail logs. Allowing public access to CloudTrail log content might aid an adversary in identifying weaknesses in the affected account's use or configuration.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access-bucket.html
# custom:
#   id: AVD-AWS-0161
#   avd_id: AVD-AWS-0161
#   provider: aws
#   service: cloudtrail
#   severity: CRITICAL
#   short_code: no-public-log-access
#   recommended_action: Restrict public access to the S3 bucket
#   frameworks:
#     default:
#       - null
#     cis-aws-1.2:
#       - "2.3"
#     cis-aws-1.4:
#       - "3.3"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudtrail
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail
#     good_examples: checks/cloud/aws/cloudtrail/no_public_log_access.tf.go
#     bad_examples: checks/cloud/aws/cloudtrail/no_public_log_access.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/cloudtrail/no_public_log_access.cf.go
#     bad_examples: checks/cloud/aws/cloudtrail/no_public_log_access.cf.go
package builtin.aws.cloudtrail.aws0161

import rego.v1

import data.lib.aws.s3

deny contains res if {
	some trail in input.aws.cloudtrail.trails
	trail.bucketname.value != ""

	some bucket in input.aws.s3.buckets
	bucket.name.value == trail.bucketname.value

	s3.bucket_has_public_exposure_acl(bucket)
	res := result.new("Trail S3 bucket is publicly exposed", bucket)
}
