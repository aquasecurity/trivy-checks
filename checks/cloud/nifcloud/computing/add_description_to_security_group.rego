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
#   aliases:
#     - nifcloud-computing-add-description-to-security-group
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
#   examples: checks/cloud/nifcloud/computing/add_description_to_security_group.yaml
package builtin.nifcloud.computing.nifcloud0002

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some sg in input.nifcloud.computing.securitygroups
	isManaged(sg)
	without_description(sg)
	res := result.new(
		"Security group does not have a description.",
		metadata.obj_by_path(sg, ["description"]),
	)
}

deny contains res if {
	some sg in input.nifcloud.computing.securitygroups
	isManaged(sg)
	sg.description.value == "Managed by Terraform"
	res := result.new("Security group explicitly uses the default description.", sg.description)
}

without_description(sg) if value.is_empty(sg.description)

without_description(sg) if not sg.description
