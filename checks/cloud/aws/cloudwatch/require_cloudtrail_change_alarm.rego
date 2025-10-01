# METADATA
# title: Ensure a log metric filter and alarm exist for CloudTrail configuration changes
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   CIS recommends that you create a metric filter and alarm for changes to CloudTrail configuration settings. Monitoring these changes helps ensure sustained visibility to activities in the account.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html
# custom:
#   id: AVD-AWS-0151
#   avd_id: AVD-AWS-0151
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-cloud-trail-change-alarm
#   recommended_action: Create an alarm to alert on CloudTrail configuration changes
#   frameworks:
#     cis-aws-1.2:
#       - "3.5"
#     cis-aws-1.4:
#       - "4.5"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0151

import rego.v1

import data.lib.aws.trails

config_changes_filter_pattern := `{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) 
|| ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}`

deny contains res if {
	some trail in trails.trails_without_filter(config_changes_filter_pattern)
	res := result.new("Cloudtrail has no IAM policy change log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(config_changes_filter_pattern)
	res := result.new("Cloudtrail has no IAM Policy change alarm", trail)
}
