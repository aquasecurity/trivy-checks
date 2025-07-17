# METADATA
# title: Ensure a log metric filter and alarm exist for unauthorized API calls
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. You can have more than one VPC in an account, and you can create a peer connection between two VPCs, enabling network traffic to route between VPCs.
#   CIS recommends that you create a metric filter and alarm for changes to VPCs. Monitoring these changes helps ensure that authentication and authorization controls remain intact.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html
# custom:
#   id: AVD-AWS-0147
#   avd_id: AVD-AWS-0147
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-unauthorised-api-call-alarm
#   recommended_action: Create an alarm to alert on unauthorized API calls
#   frameworks:
#     cis-aws-1.2:
#       - "3.1"
#     cis-aws-1.4:
#       - "4.1"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0147

import rego.v1

import data.lib.aws.trails

pattern := `($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")`

deny contains res if {
	some trail in trails.trails_without_filter(pattern)
	res := result.new("Cloudtrail has no unauthorized API log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(pattern)
	res := result.new("Cloudtrail has no unauthorized API alarm", trail)
}
