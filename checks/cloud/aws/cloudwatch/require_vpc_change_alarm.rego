# METADATA
# title: Ensure a log metric filter and alarm exist for VPC changes
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   You can have more than one VPC in an account, and you can create a peer connection between two VPCs, enabling network traffic to route between VPCs.
#   CIS recommends that you create a metric filter and alarm for changes to VPCs. Monitoring these changes helps ensure that authentication and authorization controls remain intact.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html
# custom:
#   id: AVD-AWS-0160
#   avd_id: AVD-AWS-0160
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-vpc-changes-alarm
#   recommended_action: Create an alarm to alert on route table changes
#   frameworks:
#     cis-aws-1.2:
#       - "3.14"
#     cis-aws-1.4:
#       - "4.14"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0160

import rego.v1

import data.lib.aws.trails

pattern := `{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}`

deny contains res if {
	some trail in trails.trails_without_filter(pattern)
	res := result.new("Cloudtrail has no vpc change log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(pattern)
	res := result.new("Cloudtrail has no vpc change alarm", trail)
}
