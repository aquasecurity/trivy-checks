# METADATA
# title: Ensure a log metric filter and alarm exist for AWS Config configuration changes
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   CIS recommends that you create a metric filter and alarm for changes to AWS Config configuration settings. Monitoring these changes helps ensure sustained visibility of configuration items in the account.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html
# custom:
#   id: AVD-AWS-0155
#   avd_id: AVD-AWS-0155
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-config-configuration-changes-alarm
#   recommended_action: Create an alarm to alert on AWS Config configuration changes
#   frameworks:
#     cis-aws-1.2:
#       - "3.9"
#     cis-aws-1.4:
#       - "4.9"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0155

import rego.v1

import data.lib.aws.trails

filter_pattern := `{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}`

deny contains res if {
	some trail in trails.trails_without_filter(filter_pattern)
	res := result.new("Cloudtrail has no Config configuration change log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(filter_pattern)
	res := result.new("Cloudtrail has no Config configuration change alarm", trail)
}