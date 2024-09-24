# METADATA
# title: Missing security group for router.
# description: |
#   Need to add a security group to your router.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/help/router/change.htm
# custom:
#   id: AVD-NIF-0016
#   avd_id: AVD-NIF-0016
#   provider: nifcloud
#   service: network
#   severity: CRITICAL
#   short_code: add-security-group-to-router
#   recommended_action: Add security group for all routers
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/router#security_group
#     good_examples: checks/cloud/nifcloud/network/add_security_group_to_router.tf.go
#     bad_examples: checks/cloud/nifcloud/network/add_security_group_to_router.tf.go
package builtin.nifcloud.network.nifcloud0016

import rego.v1

deny contains res if {
	some router in input.nifcloud.network.routers
	not has_security_group(router)
	res := result.new(
		"Router does not have a securiy group.",
		object.get(router, "securitygroup", router),
	)
}

has_security_group(router) if router.securitygroup.value != ""
