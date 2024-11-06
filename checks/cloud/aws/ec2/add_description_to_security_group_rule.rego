# METADATA
# title: Missing description for security group rule.
# description: |
#   Security group rules should include a description for auditing purposes.
#
#   Simplifies auditing, debugging, and managing security groups.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html
# custom:
#   id: AVD-AWS-0124
#   avd_id: AVD-AWS-0124
#   aliases:
#     - aws-vpc-add-description-to-security-group-rule
#   provider: aws
#   service: ec2
#   severity: LOW
#   short_code: add-description-to-security-group-rule
#   recommended_action: Add descriptions for all security groups rules
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule
#     good_examples: checks/cloud/aws/ec2/add_description_to_security_group_rule.yaml
#     bad_examples: checks/cloud/aws/ec2/add_description_to_security_group_rule.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/ec2/add_description_to_security_group_rule.yaml
#     bad_examples: checks/cloud/aws/ec2/add_description_to_security_group_rule.yaml
package builtin.aws.ec2.aws0124

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some group in input.aws.ec2.securitygroups
	some rule in array.concat(
		object.get(group, "egressrules", []),
		object.get(group, "ingressrules", []),
	)
	without_description(rule)
	res := result.new(
		"Security group rule does not have a description.",
		metadata.obj_by_path(rule, ["description"]),
	)
}

without_description(rule) if value.is_empty(rule.description)

without_description(rule) if not rule.description
