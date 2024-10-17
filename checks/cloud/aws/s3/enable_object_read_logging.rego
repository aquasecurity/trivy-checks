# METADATA
# title: S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets.
# description: |
#   Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity within your S3 Buckets using Amazon CloudWatch Events.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html
# custom:
#   id: AVD-AWS-0172
#   avd_id: AVD-AWS-0172
#   provider: aws
#   service: s3
#   severity: LOW
#   short_code: enable-object-read-logging
#   recommended_action: Enable Object-level logging for S3 buckets.
#   frameworks:
#     cis-aws-1.4:
#       - "3.11"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning
#     good_examples: checks/cloud/aws/s3/enable_object_read_logging.yaml
#     bad_examples: checks/cloud/aws/s3/enable_object_read_logging.yaml
package builtin.aws.s3.aws0172

import rego.v1

deny contains res if {
	some bucket in input.aws.s3.buckets
	not has_read_logging(bucket)
	res := result.new(
		"Bucket does not have object-level read logging enabled",
		bucket,
	)
}

has_read_logging(bucket) if {
	some selector in input.aws.cloudtrail.trails[_].eventselectors
	selector.readwritetype.value != "WriteOnly"

	some dataresource in selector.dataresources
	dataresource.type.value == "AWS::S3::Object"

	some partial in dataresource.values
	partial.value in {"arn:aws:s3", sprintf("arn:aws:s3:::%s/", [bucket.name.value])}
}
