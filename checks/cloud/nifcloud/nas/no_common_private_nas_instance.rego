# METADATA
# title: The nas instance has common private network
# description: |
#   When handling sensitive data between servers, please consider using a private LAN to isolate the private side network from the shared network.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/service/plan.htm
# custom:
#   id: AVD-NIF-0013
#   avd_id: AVD-NIF-0013
#   aliases:
#     - nifcloud-nas-no-common-private-nas-instance
#   provider: nifcloud
#   service: nas
#   severity: LOW
#   short_code: no-common-private-nas-instance
#   recommended_action: Use private LAN
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: nas
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_instance#network_id
#     good_examples: checks/cloud/nifcloud/nas/no_common_private_nas_instance.yaml
#     bad_examples: checks/cloud/nifcloud/nas/no_common_private_nas_instance.yaml
package builtin.nifcloud.nas.nifcloud0013

import rego.v1

deny contains res if {
	some instance in input.nifcloud.nas.nasinstances
	instance.networkid.value == "net-COMMON_PRIVATE"
	res := result.new("The nas instance has common private network", instance.networkid)
}
