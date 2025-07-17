# METADATA
# title: Ensure a log metric filter and alarm exist for IAM policy changes
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   CIS recommends that you create a metric filter and alarm for changes made to IAM policies. Monitoring these changes helps ensure that authentication and authorization controls remain intact.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html
# custom:
#   id: AVD-AWS-0150
#   avd_id: AVD-AWS-0150
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-iam-policy-change-alarm
#   recommended_action: Create an alarm to alert on IAM Policy changes
#   frameworks:
#     cis-aws-1.2:
#       - "3.4"
#     cis-aws-1.4:
#       - "4.4"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0150

import rego.v1

import data.lib.aws.trails

filter_pattern := `{($.eventName=DeleteGroupPolicy) || 
($.eventName=DeleteRolePolicy) || 
($.eventName=DeleteUserPolicy) || 
($.eventName=PutGroupPolicy) || 
($.eventName=PutRolePolicy) || 
($.eventName=PutUserPolicy) || 
($.eventName=CreatePolicy) || 
($.eventName=DeletePolicy) || 
($.eventName=CreatePolicyVersion) || 
($.eventName=DeletePolicyVersion) || 
($.eventName=AttachRolePolicy) ||
($.eventName=DetachRolePolicy) ||
($.eventName=AttachUserPolicy) || 
($.eventName=DetachUserPolicy) || 
($.eventName=AttachGroupPolicy) || 
($.eventName=DetachGroupPolicy)}`

deny contains res if {
	some trail in trails.trails_without_filter(filter_pattern)
	res := result.new("Cloudtrail has no IAM policy change log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(filter_pattern)
	res := result.new("Cloudtrail has no IAM Policy change alarm", trail)
}
