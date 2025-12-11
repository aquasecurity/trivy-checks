# METADATA
# title: Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   CIS recommends that you create a metric filter and alarm for failed console authentication attempts. Monitoring failed console logins might decrease lead time to detect an attempt to brute-force a credential, which might provide an indicator, such as source IP, that you can use in other event correlations.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html
# custom:
#   id: AVD-AWS-0152
#   avd_id: AVD-AWS-0152
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-console-login-failures-alarm
#   recommended_action: Create an alarm to alert on console login failures
#   frameworks:
#     cis-aws-1.4:
#       - "4.6"
#     cis-aws-1.2:
#       - "3.6"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0152

import rego.v1

import data.lib.aws.trails

filter_pattern := `{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}`

deny contains res if {
	some trail in trails.trails_without_filter(filter_pattern)
	res := result.new("Cloudtrail has no console login failure log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(filter_pattern)
	res := result.new("ClouCloudtrail has no console login failure alarm", trail)
}
