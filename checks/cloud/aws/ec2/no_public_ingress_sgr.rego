# METADATA
# title: Security groups should not allow unrestricted ingress to SSH or RDP from any IP address.
# description: |
#   Security groups provide stateful filtering of ingress and egress network traffic to AWS
#   resources. It is recommended that no security group allows unrestricted ingress access to
#   remote server administration ports, such as SSH to port 22 and RDP to port 3389.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html
#   - https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-13
#   - https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-14
# custom:
#   id: AVD-AWS-0107
#   avd_id: AVD-AWS-0107
#   provider: aws
#   service: ec2
#   severity: HIGH
#   short_code: no-public-ingress-sgr
#   recommended_action: Set a more restrictive CIDR range
#   frameworks:
#     default:
#       - null
#     cis-aws-1.2:
#       - "4.1"
#       - "4.2"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   examples: checks/cloud/aws/ec2/no_public_ingress_sgr.yaml
package builtin.aws.ec2.aws0107

import rego.v1

import data.lib.net

deny contains res if {
	some group in input.aws.ec2.securitygroups
	some rule in group.ingressrules
	net.is_tcp_or_udp_protocol(rule.protocol.value)
	net.is_ssh_or_rdp_port(rule)
	some block in rule.cidrs
	net.cidr_allows_all_ips(block.value)
	res := result.new(
		"Security group rule allows unrestricted ingress from any IP address.",
		block,
	)
}
