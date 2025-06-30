# METADATA
# title: Missing description for nas security group.
# description: |
#   NAS security groups should include a description for auditing purposes.
#
#   Simplifies auditing, debugging, and managing nas security groups.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/help/nas/fw_new.htm
# custom:
#   id: AVD-NIF-0015
#   avd_id: AVD-NIF-0015
#   aliases:
#     - nifcloud-nas-add-description-to-nas-security-group
#   provider: nifcloud
#   service: nas
#   severity: LOW
#   short_code: add-description-to-nas-security-group
#   recommended_action: Add descriptions for all nas security groups
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: nas
#             provider: nifcloud
#   examples: checks/cloud/nifcloud/nas/add_description_to_nas_security_group.yaml
package builtin.nifcloud.nas.nifcloud0015

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some sg in input.nifcloud.nas.nassecuritygroups
	isManaged(sg)
	without_description(sg)
	res := result.new(
		"NAS security group does not have a description.",
		metadata.obj_by_path(sg, ["description"]),
	)
}

deny contains res if {
	some sg in input.nifcloud.nas.nassecuritygroups
	isManaged(sg)
	sg.description.value == "Managed by Terraform"
	res := result.new(
		"NAS security group explicitly uses the default description.",
		sg.description,
	)
}

without_description(sg) if value.is_empty(sg.description)

without_description(sg) if not sg.description
