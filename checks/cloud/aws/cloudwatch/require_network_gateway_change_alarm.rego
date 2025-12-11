# METADATA
# title: Ensure a log metric filter and alarm exist for changes to network gateways
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   Network gateways are required to send and receive traffic to a destination outside a VPC.
#   CIS recommends that you create a metric filter and alarm for changes to network gateways. Monitoring these changes helps ensure that all ingress and egress traffic traverses the VPC border via a controlled path.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html
# custom:
#   id: AVD-AWS-0158
#   avd_id: AVD-AWS-0158
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-network-gateway-changes-alarm
#   recommended_action: Create an alarm to alert on network gateway changes
#   frameworks:
#     cis-aws-1.2:
#       - "3.12"
#     cis-aws-1.4:
#       - "4.12"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0158

import rego.v1

import data.lib.aws.trails

filter_pattern := `{($.eventName=CreateCustomerGateway) || 
					($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || 
					($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || 
					($.eventName=DetachInternetGateway)}`

deny contains res if {
	some trail in trails.trails_without_filter(filter_pattern)
	res := result.new("Cloudtrail has no network gateway change log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(filter_pattern)
	res := result.new("Cloudtrail has no network gateway change alarm", trail)
}
