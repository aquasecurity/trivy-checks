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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule
#     good_examples: checks/cloud/aws/ec2/add_description_to_security_group.tf.go
#     bad_examples: checks/cloud/aws/ec2/add_description_to_security_group.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ec2/add_description_to_security_group.cf.go
#     bad_examples: checks/cloud/aws/ec2/add_description_to_security_group.cf.go
package builtin.aws.ec2.aws0099

import rego.v1

deny contains res if {
	some sg in input.aws.ec2.securitygroups
	sg.__defsec_metadata.managed
	sg.description.value == ""
	res := result.new("Security group does not have a description.", sg)
}

deny contains res if {
	some sg in input.aws.ec2.securitygroups
	sg.__defsec_metadata.managed
	sg.description.value == "Managed by Terraform"
	res := result.new("Security group explicitly uses the default description.", sg)
}
