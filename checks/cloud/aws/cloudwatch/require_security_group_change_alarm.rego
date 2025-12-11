# METADATA
# title: Ensure a log metric filter and alarm exist for security group changes
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   Security groups are a stateful packet filter that controls ingress and egress traffic in a VPC.
#   CIS recommends that you create a metric filter and alarm for changes to security groups. Monitoring these changes helps ensure that resources and services aren't unintentionally exposed.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html
# custom:
#   id: AVD-AWS-0156
#   avd_id: AVD-AWS-0156
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-sg-change-alarms
#   recommended_action: Create an alarm to alert on security group changes
#   frameworks:
#     cis-aws-1.2:
#       - "3.10"
#     cis-aws-1.4:
#       - "4.10"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0156

import rego.v1

import data.lib.aws.trails

pattern := `{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}`

deny contains res if {
	some trail in trails.trails_without_filter(pattern)
	res := result.new("Cloudtrail has no Security Group change log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(pattern)
	res := result.new("Cloudtrail has no Security Group change alarm", trail)
}
