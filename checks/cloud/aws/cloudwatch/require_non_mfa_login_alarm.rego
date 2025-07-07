# METADATA
# title: Ensure a log metric filter and alarm exist for AWS Management Console sign-in without MFA
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   CIS recommends that you create a metric filter and alarm console logins that  aren't protected by MFA. Monitoring for single-factor console logins increases visibility into accounts that aren't protected by MFA.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://aws.amazon.com/iam/features/mfa/
# custom:
#   id: AVD-AWS-0148
#   avd_id: AVD-AWS-0148
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-non-mfa-login-alarm
#   recommended_action: Create an alarm to alert on non MFA logins
#   frameworks:
#     cis-aws-1.2:
#       - "3.2"
#     cis-aws-1.4:
#       - "4.2"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0148

import rego.v1

import data.lib.aws.trails

# TODO(nikpivkin): string can be escaped
# https://github.com/cisagov/crossfeed/blob/7da8691c302267015bb45a9ad4485dd87e554fab/infrastructure/log_filters.tf#L28
filter_pattern := `($.eventName = "ConsoleLogin") && 
($.additionalEventData.MFAUsed != "Yes") && 
($.userIdentity.type=="IAMUser") && 
($.responseElements.ConsoleLogin == "Success")`

deny contains res if {
	some trail in trails.trails_without_filter(filter_pattern)
	res := result.new("Cloudtrail has no non-MFA login log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(filter_pattern)
	res := result.new("Cloudtrail has no non-MFA login alarm", trail)
}
