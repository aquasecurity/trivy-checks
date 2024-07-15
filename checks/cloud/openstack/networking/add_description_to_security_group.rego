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
#   terraform:
#     good_examples: checks/cloud/openstack/networking/add_description_to_security_group.tf.go
#     bad_examples: checks/cloud/openstack/networking/add_description_to_security_group.tf.go
package builtin.openstack.networking.openstack0005

import rego.v1

deny contains res if {
	some sg in input.openstack.networking.securitygroups
	sg.description.value == ""
	res := result.new("Security group rule allows egress to multiple public addresses.", sg.description)
}
