# METADATA
# title: Missing description for security group.
# description: |
#   Security groups should include a description for auditing purposes.
#
#   Simplifies auditing, debugging, and managing security groups.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html
# custom:
#   id: AVD-AWS-0099
#   avd_id: AVD-AWS-0099
#   aliases:
#     - aws-vpc-add-description-to-security-group
#   provider: aws
#   service: ec2
#   severity: LOW
#   short_code: add-description-to-security-group
#   recommended_action: Add descriptions for all security groups
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   examples: checks/cloud/aws/ec2/add_description_to_security_group.yaml
package builtin.aws.ec2.aws0099

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some sg in input.aws.ec2.securitygroups
	isManaged(sg)
	not sg.isdefault.value
	without_description(sg)
	res := result.new(
		"Security group does not have a description.",
		metadata.obj_by_path(sg, ["description"]),
	)
}

deny contains res if {
	some sg in input.aws.ec2.securitygroups
	isManaged(sg)
	not sg.isdefault.value
	sg.description.value == "Managed by Terraform"
	res := result.new("Security group explicitly uses the default description.", sg.description)
}

without_description(sg) if value.is_empty(sg.description)

without_description(sg) if not sg.description
