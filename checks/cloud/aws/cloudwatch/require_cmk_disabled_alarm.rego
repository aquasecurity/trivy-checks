# METADATA
# title: Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   CIS recommends that you create a metric filter and alarm for customer managed keys that have changed state to disabled or scheduled deletion. Data encrypted with disabled or deleted keys is no longer accessible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html
# custom:
#   id: AVD-AWS-0153
#   avd_id: AVD-AWS-0153
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-cmk-disabled-alarm
#   recommended_action: Create an alarm to alert on CMKs being disabled or scheduled for deletion
#   frameworks:
#     cis-aws-1.2:
#       - "3.7"
#     cis-aws-1.4:
#       - "4.7"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0153

import rego.v1

import data.lib.aws.trails

disabled_filter_pattern := `{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}`

deny contains res if {
	some trail in trails.trails_without_filter(disabled_filter_pattern)
	res := result.new("Cloudtrail has no CMK disabled log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(disabled_filter_pattern)
	res := result.new("Cloudtrail has no CMK disabled of scheduled deletion alarm", trail)
}
