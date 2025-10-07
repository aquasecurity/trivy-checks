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
#   - https://pfs.nifcloud.com/help/fw/rule_new.htm
# custom:
#   id: AVD-NIF-0003
#   avd_id: AVD-NIF-0003
#   aliases:
#     - nifcloud-computing-add-description-to-security-group-rule
#   provider: nifcloud
#   service: computing
#   severity: LOW
#   short_code: add-description-to-security-group-rule
#   recommended_action: Add descriptions for all security groups rules
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: computing
#             provider: nifcloud
#   examples: checks/cloud/nifcloud/computing/add_description_to_security_group_rule.yaml
package builtin.nifcloud.computing.nifcloud0003

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

rules := [
rule |
	some sg in input.nifcloud.computing.securitygroups
	some rule in array.concat(
		object.get(sg, "ingressrules", []),
		object.get(sg, "egressrules", []),
	)
]

deny contains res if {
	some rule in rules
	isManaged(rule)
	without_description(rule)
	res := result.new(
		"Security group rule does not have a description.",
		metadata.obj_by_path(rule, ["description"]),
	)
}

without_description(rule) if value.is_empty(rule.description)

without_description(rule) if not rule.description
