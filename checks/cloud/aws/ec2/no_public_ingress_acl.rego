# METADATA
# title: Network ACLs should not allow unrestricted ingress to SSH or RDP from any IP address.
# description: |
#   The Network Access Control List (NACL) function provide stateless filtering of ingress and
#   egress network traffic to AWS resources. It is recommended that no NACL allows
#   unrestricted ingress access to remote server administration ports, such as SSH to port 22
#   and RDP to port 3389.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
#   - https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-21
# custom:
#   id: AVD-AWS-0105
#   avd_id: AVD-AWS-0105
#   aliases:
#     - aws-vpc-no-public-ingress-acl
#   provider: aws
#   service: ec2
#   severity: MEDIUM
#   short_code: no-public-ingress-acl
#   recommended_action: Set a more restrictive CIDR range
#   frameworks:
#     default:
#       - null
#     cis-aws-1.4:
#       - "5.1"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   examples: checks/cloud/aws/ec2/no_public_ingress_acl.yaml
package builtin.aws.ec2.aws0105

import rego.v1

import data.lib.net

deny contains res if {
	some acl in input.aws.ec2.networkacls
	some rule in acl.rules
	is_ingress(rule)
	is_allow(rule)
	net.is_tcp_protocol(rule.protocol.value)
	net.is_ssh_or_rdp_port(rule)
	some block in rule.cidrs
	net.cidr_allows_all_ips(block.value)
	res := result.new(
		"Network ACL rule allows unrestricted ingress from any IP address.",
		block,
	)
}

is_ingress(rule) if rule.type.value == "ingress"

is_allow(rule) if rule.action.value == "allow"
