# METADATA
# title: Ensure a log metric filter and alarm exist for usage of root user
# description: |
#   You can do real-time monitoring of API calls directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   CIS recommends that you create a metric filter and alarm for root user login attempts. Monitoring for root user logins provides visibility into the use of a fully privileged account and an opportunity to reduce the use of it.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://aws.amazon.com/iam/features/mfa/
# custom:
#   id: AVD-AWS-0149
#   avd_id: AVD-AWS-0149
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-root-user-usage-alarm
#   recommended_action: Create an alarm to alert on root user login
#   frameworks:
#     cis-aws-1.2:
#       - "3.3"
#     cis-aws-1.4:
#       - "4.3"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0149

import rego.v1

import data.lib.aws.trails

pattern := `$.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && &.eventType != "AwsServiceEvent"`

deny contains res if {
	some trail in trails.trails_without_filter(pattern)
	res := result.new("Cloudtrail has no root user usage log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(pattern)
	res := result.new("Cloudtrail has no root user usage alarm", trail)
}
