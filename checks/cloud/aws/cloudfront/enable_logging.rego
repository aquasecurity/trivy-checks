# METADATA
# title: Cloudfront distribution should have Access Logging configured
# description: |
#   You should configure CloudFront Access Logging to create log files that contain detailed information about every user request that CloudFront receives
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html
# custom:
#   id: AWS-0010
#   aliases:
#     - AVD-AWS-0010
#     - enable-logging
#   long_id: aws-cloudfront-enable-logging
#   provider: aws
#   service: cloudfront
#   severity: MEDIUM
#   recommended_action: Enable logging for CloudFront distributions
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudfront
#             provider: aws
#   examples: checks/cloud/aws/cloudfront/enable_logging.yaml
package builtin.aws.cloudfront.aws0010

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some dist in input.aws.cloudfront.distributions
	without_logging_bucket(dist)
	res := result.new(
		"Distribution does not have logging enabled",
		metadata.obj_by_path(dist, ["logging", "bucket"]),
	)
}

without_logging_bucket(dist) if value.is_empty(dist.logging.bucket)

without_logging_bucket(dist) if not dist.logging.bucket
