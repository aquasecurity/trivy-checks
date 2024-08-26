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
#   - https://pfs.nifcloud.com/help/fw/change.htm
# custom:
#   id: AVD-NIF-0002
#   avd_id: AVD-NIF-0002
#   provider: nifcloud
#   service: computing
#   severity: LOW
#   short_code: add-description-to-security-group
#   recommended_action: Add descriptions for all security groups
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: computing
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group#description
#     good_examples: checks/cloud/nifcloud/computing/add_description_to_security_group.tf.go
#     bad_examples: checks/cloud/nifcloud/computing/add_description_to_security_group.tf.go
package builtin.nifcloud.computing.nifcloud0002

import rego.v1

deny contains res if {
	some sg in input.nifcloud.computing.securitygroups
	sg.description.value == ""
	res := result.new("Security group does not have a description.", sg.description)
}

deny contains res if {
	some sg in input.nifcloud.computing.securitygroups
	sg.description.value == "Managed by Terraform"
	res := result.new("Security group explicitly uses the default description.", sg.description)
}
