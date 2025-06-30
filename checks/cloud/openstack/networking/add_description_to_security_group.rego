# METADATA
# title: Missing description for security group.
# description: |
#   Security groups should include a description for auditing purposes. Simplifies auditing, debugging, and managing security groups.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-OPNSTK-0005
#   avd_id: AVD-OPNSTK-0005
#   provider: openstack
#   service: networking
#   severity: MEDIUM
#   short_code: describe-security-group
#   recommended_action: Add descriptions for all security groups
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: networking
#             provider: openstack
#   examples: checks/cloud/openstack/networking/add_description_to_security_group.yaml
package builtin.openstack.networking.openstack0005

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some sg in input.openstack.networking.securitygroups
	isManaged(sg)
	without_description(sg)
	res := result.new(
		"Network security group does not have a description.",
		metadata.obj_by_path(sg, ["description"]),
	)
}

without_description(sg) if value.is_empty(sg.description)

without_description(sg) if not sg.description
