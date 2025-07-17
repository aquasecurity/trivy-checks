# METADATA
# title: Enable disk encryption on managed disk
# description: |
#   Manage disks should be encrypted at rest. When specifying the <code>encryption_settings</code> block, the enabled attribute should be set to <code>true</code>.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption
# custom:
#   id: AVD-AZU-0038
#   avd_id: AVD-AZU-0038
#   provider: azure
#   service: compute
#   severity: HIGH
#   short_code: enable-disk-encryption
#   recommended_action: Enable encryption on managed disks
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: azure
#   examples: checks/cloud/azure/compute/enable_disk_encryption.yaml
package builtin.azure.compute.azure0038

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some disk in input.azure.compute.manageddisks
	isManaged(disk)
	not disk.encryption.enabled.value
	res := result.new(
		"Managed disk is not encrypted.",
		metadata.obj_by_path(disk, ["encryption", "enabled"]),
	)
}
