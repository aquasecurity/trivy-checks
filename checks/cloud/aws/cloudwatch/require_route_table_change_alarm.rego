# METADATA
# title: Ensure a log metric filter and alarm exist for route table changes
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   Routing tables route network traffic between subnets and to network gateways.
#   CIS recommends that you create a metric filter and alarm for changes to route tables. Monitoring these changes helps ensure that all VPC traffic flows through an expected path.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html
# custom:
#   id: AVD-AWS-0159
#   avd_id: AVD-AWS-0159
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-network-gateway-changes-alarm
#   recommended_action: Create an alarm to alert on route table changes
#   frameworks:
#     cis-aws-1.2:
#       - "3.13"
#     cis-aws-1.4:
#       - "4.13"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0159

import rego.v1

import data.lib.aws.trails

pattern := `{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}`

deny contains res if {
	some trail in trails.trails_without_filter(pattern)
	res := result.new("Cloudtrail has no route table change log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(pattern)
	res := result.new("Cloudtrail has no route table change alarm", trail)
}
