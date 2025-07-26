# METADATA
# title: VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet "Rejects" for VPCs.
# description: |
#   VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html
# custom:
#   id: AWS-0178
#   aliases:
#     - AVD-AWS-0178
#     - aws-autoscaling-enable-at-rest-encryption
#     - require-vpc-flow-logs-for-all-vpcs
#   long_id: aws-ec2-require-vpc-flow-logs-for-all-vpcs
#   provider: aws
#   service: ec2
#   severity: MEDIUM
#   recommended_action: Enable flow logs for VPC
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   examples: checks/cloud/aws/ec2/require_vpc_flow_logs_for_all_vpcs.yaml
package builtin.aws.ec2.aws0178

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some vpc in input.aws.ec2.vpcs
	logs_disabled(vpc)
	res := result.new(
		"VPC does not have VPC Flow Logs enabled.",
		metadata.obj_by_path(vpc, ["flowlogsenabled"]),
	)
}

logs_disabled(vpc) if value.is_false(vpc.flowlogsenabled)

logs_disabled(vpc) if not vpc.flowlogsenabled
