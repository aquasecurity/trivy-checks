# METADATA
# title: An egress security group rule allows traffic to /0.
# description: |
#   Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/centralized-egress-to-internet.html
# custom:
#   id: AVD-AWS-0104
#   avd_id: AVD-AWS-0104
#   aliases:
#     - aws-vpc-no-public-egress-sgr
#   provider: aws
#   service: ec2
#   severity: CRITICAL
#   short_code: no-public-egress-sgr
#   recommended_action: Set a more restrictive cidr range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group
#     good_examples: checks/cloud/aws/ec2/no_public_egress_sgr.yaml
#     bad_examples: checks/cloud/aws/ec2/no_public_egress_sgr.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/ec2/no_public_egress_sgr.yaml
#     bad_examples: checks/cloud/aws/ec2/no_public_egress_sgr.yaml
package builtin.aws.ec2.aws0104

import rego.v1

deny contains res if {
	some rule in input.aws.ec2.securitygroups[_].egressrules
	some block in rule.cidrs
	cidr.is_public(block.value)
	cidr.count_addresses(block.value) > 1
	res := result.new(
		"Security group rule allows egress to multiple public internet addresses.",
		block,
	)
}
