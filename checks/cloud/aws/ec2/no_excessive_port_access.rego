# METADATA
# title: An Network ACL rule allows ALL ports.
# description: |
#   Ensure access to specific required ports is allowed, and nothing else.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
# custom:
#   id: AVD-AWS-0102
#   avd_id: AVD-AWS-0102
#   provider: aws
#   service: ec2
#   severity: CRITICAL
#   short_code: no-excessive-port-access
#   recommended_action: Set specific allowed ports
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl_rule#to_port
#     good_examples: checks/cloud/aws/ec2/no_excessive_port_access.tf.go
#     bad_examples: checks/cloud/aws/ec2/no_excessive_port_access.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ec2/no_excessive_port_access.cf.go
#     bad_examples: checks/cloud/aws/ec2/no_excessive_port_access.cf.go
package builtin.aws.ec2.aws0102

import rego.v1

all_protocols := {"all", "-1"}

deny contains res if {
	some rule in input.aws.ec2.networkacls[_].rules
	rule.action.value == "allow"
	rule.protocol.value in all_protocols
	res := result.new("Network ACL rule allows access using ALL ports.", rule.protocol)
}
