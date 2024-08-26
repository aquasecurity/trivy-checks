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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group_rule#description
#     good_examples: checks/cloud/nifcloud/computing/add_description_to_security_group_rule.tf.go
#     bad_examples: checks/cloud/nifcloud/computing/add_description_to_security_group_rule.tf.go
package builtin.nifcloud.computing.nifcloud0003

import rego.v1

deny contains res if {
	some sg in input.nifcloud.computing.securitygroups
	some rule in array.concat(
		object.get(sg, "ingressrules", []),
		object.get(sg, "egressrules", []),
	)

	rule.description.value == ""
	res := result.new("Security group rule does not have a description.", rule.description)
}
