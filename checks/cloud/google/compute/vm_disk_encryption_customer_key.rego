# METADATA
# title: VM disks should be encrypted with Customer Supplied Encryption Keys
# description: |
#   Using unmanaged keys makes rotation and general management difficult.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0033
#   avd_id: AVD-GCP-0033
#   provider: google
#   service: compute
#   severity: LOW
#   short_code: vm-disk-encryption-customer-key
#   recommended_action: Use managed keys
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/vm_disk_encryption_customer_key.yaml
package builtin.google.compute.google0033

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some instance in input.google.compute.instances
	disks := array.concat(
		object.get(instance, "bootdisks", []),
		object.get(instance, "attacheddisks", []),
	)

	some disk in disks

	disk_is_not_encrypted(disk)
	res := result.new(
		"Instance disk encryption does not use a customer managed key.",
		metadata.obj_by_path(disk, ["encryption", "kmskeylink"]),
	)
}

disk_is_not_encrypted(disk) if value.is_empty(disk.encryption.kmskeylink)

disk_is_not_encrypted(disk) if not disk.encryption.kmskeylink
