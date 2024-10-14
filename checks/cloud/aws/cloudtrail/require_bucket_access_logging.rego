# METADATA
# title: You should enable bucket access logging on the CloudTrail S3 bucket.
# description: |
#   Amazon S3 bucket access logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed.
#   CIS recommends that you enable bucket access logging on the CloudTrail S3 bucket.
#   By enabling S3 bucket logging on target S3 buckets, you can capture all events that might affect objects in a target bucket. Configuring logs to be placed in a separate bucket enables access to log information, which can be useful in security and incident response workflows.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html
# custom:
#   id: AVD-AWS-0163
#   avd_id: AVD-AWS-0163
#   provider: aws
#   service: cloudtrail
#   severity: LOW
#   short_code: require-bucket-access-logging
#   recommended_action: Enable access logging on the bucket
#   frameworks:
#     default:
#       - null
#     cis-aws-1.2:
#       - "2.6"
#     cis-aws-1.4:
#       - "3.6"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudtrail
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail
#     good_examples: checks/cloud/aws/cloudtrail/require_bucket_access_logging.yaml
#     bad_examples: checks/cloud/aws/cloudtrail/require_bucket_access_logging.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/cloudtrail/require_bucket_access_logging.yaml
#     bad_examples: checks/cloud/aws/cloudtrail/require_bucket_access_logging.yaml
package builtin.aws.cloudtrail.aws0163

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some trail in input.aws.cloudtrail.trails
	trail.bucketname.value != ""

	some bucket in input.aws.s3.buckets
	bucket.name.value == trail.bucketname.value
	not bucket.logging.enabled.value

	res := result.new(
		"Trail S3 bucket does not have logging enabled",
		metadata.obj_by_path(bucket, ["name"]),
	)
}
