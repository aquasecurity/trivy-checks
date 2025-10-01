# METADATA
# title: Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)
# description: |
#   You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.
#   NACLs are used as a stateless packet filter to control ingress and egress traffic for subnets in a VPC.
#   CIS recommends that you create a metric filter and alarm for changes to NACLs. Monitoring these changes helps ensure that AWS resources and services aren't unintentionally exposed.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html
# custom:
#   id: AVD-AWS-0157
#   avd_id: AVD-AWS-0157
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: require-nacl-changes-alarm
#   recommended_action: Create an alarm to alert on network acl changes
#   frameworks:
#     cis-aws-1.4:
#       - "4.11"
#     cis-aws-1.2:
#       - "3.11"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.aws0157

import rego.v1

import data.lib.aws.trails

filter_pattern := `{($.eventName=CreateNetworkAcl) || 
					($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || 
					($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || 
					($.eventName=ReplaceNetworkAclAssociation)}`

deny contains res if {
	some trail in trails.trails_without_filter(filter_pattern)
	res := result.new("Cloudtrail has no network ACL change log filter", trail)
}

deny contains res if {
	some trail in trails.trails_without_alarm_for_filter(filter_pattern)
	res := result.new("Cloudtrail has no network ACL change alarm", trail)
}
