# METADATA
# title: An ingress security group rule allows traffic from /0.
# description: |
#   Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html
# custom:
#   id: AVD-AWS-0107
#   avd_id: AVD-AWS-0107
#   provider: aws
#   service: ec2
#   severity: CRITICAL
#   short_code: no-public-ingress-sgr
#   recommended_action: Set a more restrictive cidr range
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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule#cidr_blocks
#     good_examples: checks/cloud/aws/ec2/no_public_ingress_sgr.tf.go
#     bad_examples: checks/cloud/aws/ec2/no_public_ingress_sgr.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ec2/no_public_ingress_sgr.cf.go
#     bad_examples: checks/cloud/aws/ec2/no_public_ingress_sgr.cf.go
package builtin.aws.ec2.aws0107

import rego.v1

deny contains res if {
	some group in input.aws.ec2.securitygroups
	some rule in group.ingressrules
	some block in rule.cidrs
	cidr.is_public(block.value)
	cidr.count_addresses(block.value) > 1
	res := result.new(
		"Security group rule allows ingress from public internet.",
		block,
	)
}
