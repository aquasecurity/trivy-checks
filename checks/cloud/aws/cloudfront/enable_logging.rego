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
#   id: AVD-AWS-0010
#   avd_id: AVD-AWS-0010
#   provider: aws
#   service: cloudfront
#   severity: MEDIUM
#   short_code: enable-logging
#   recommended_action: Enable logging for CloudFront distributions
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudfront
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#logging_config
#     good_examples: checks/cloud/aws/cloudfront/enable_logging.yaml
#     bad_examples: checks/cloud/aws/cloudfront/enable_logging.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/cloudfront/enable_logging.yaml
#     bad_examples: checks/cloud/aws/cloudfront/enable_logging.yaml
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
