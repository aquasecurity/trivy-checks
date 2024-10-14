# METADATA
# title: CloudTrail logs should be stored in S3 and also sent to CloudWatch Logs
# description: |
#   Realtime log analysis is not available without enabling CloudWatch logging.
#
#   CloudTrail is a web service that records AWS API calls made in a given account. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service.
#
#   CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs in a specified Amazon S3 bucket for long-term analysis, you can perform real-time analysis by configuring CloudTrail to send logs to CloudWatch Logs.
#
#   For a trail that is enabled in all Regions in an account, CloudTrail sends log files from all those Regions to a CloudWatch Logs log group.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html#send-cloudtrail-events-to-cloudwatch-logs-console
# custom:
#   id: AVD-AWS-0162
#   avd_id: AVD-AWS-0162
#   provider: aws
#   service: cloudtrail
#   severity: LOW
#   short_code: ensure-cloudwatch-integration
#   recommended_action: Enable logging to CloudWatch
#   frameworks:
#     default:
#       - null
#     cis-aws-1.2:
#       - "2.4"
#     cis-aws-1.4:
#       - "3.4"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudtrail
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail
#     good_examples: checks/cloud/aws/cloudtrail/ensure_cloudwatch_integration.yaml
#     bad_examples: checks/cloud/aws/cloudtrail/ensure_cloudwatch_integration.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/cloudtrail/ensure_cloudwatch_integration.yaml
#     bad_examples: checks/cloud/aws/cloudtrail/ensure_cloudwatch_integration.yaml
package builtin.aws.cloudtrail.aws0162

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some trail in input.aws.cloudtrail.trails
	logging_is_not_configured(trail)
	res := result.new(
		"Trail does not have CloudWatch logging configured",
		metadata.obj_by_path(trail, ["cloudwatchlogsloggrouparn"]),
	)
}

logging_is_not_configured(trail) if value.is_empty(trail.cloudwatchlogsloggrouparn)

logging_is_not_configured(trail) if not trail.cloudwatchlogsloggrouparn
