# METADATA
# title: Missing security group for instance.
# description: |
#   Need to add a security group to your instance.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/help/server/change_fw.htm
# custom:
#   id: AVD-NIF-0004
#   avd_id: AVD-NIF-0004
#   provider: nifcloud
#   service: computing
#   severity: CRITICAL
#   short_code: add-security-group-to-instance
#   recommended_action: Add security group for all instances
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: computing
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/instance#security_group
#     good_examples: checks/cloud/nifcloud/computing/add_security_group_to_instance.tf.go
#     bad_examples: checks/cloud/nifcloud/computing/add_security_group_to_instance.tf.go
package builtin.nifcloud.computing.nifcloud0004

import rego.v1

deny contains res if {
	some instance in input.nifcloud.computing.instances
	instance.securitygroup.value == ""
	res := result.new("Instance does not have a securiy group.", instance.securitygroup)
}
