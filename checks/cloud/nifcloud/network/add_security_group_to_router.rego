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
#   aliases:
#     - nifcloud-computing-add-security-group-to-router
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
#     good_examples: checks/cloud/nifcloud/network/add_security_group_to_router.yaml
#     bad_examples: checks/cloud/nifcloud/network/add_security_group_to_router.yaml
package builtin.nifcloud.network.nifcloud0016

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some router in input.nifcloud.network.routers
	without_sg(router)
	res := result.new("Router does not have a securiy group.", router.securitygroup)
}

without_sg(router) if value.is_empty(router.securitygroup)

without_sg(router) if not router.securitygroup
