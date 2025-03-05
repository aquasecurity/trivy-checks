# METADATA
# title: Disks should be encrypted with customer managed encryption keys
# description: |
#   Using unmanaged keys makes rotation and general management difficult.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0034
#   avd_id: AVD-GCP-0034
#   provider: google
#   service: compute
#   severity: LOW
#   short_code: disk-encryption-customer-key
#   recommended_action: Use managed keys to encrypt disks.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/disk_encryption_customer_key.yaml
package builtin.google.compute.google0034

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some disk in input.google.compute.disks
	disk_not_encrypted(disk)
	res := result.new(
		"Disk is not encrypted with a customer managed key.",
		metadata.obj_by_path(disk, ["encryption", "kmskeylink"]),
	)
}

disk_not_encrypted(disk) if value.is_empty(disk.encryption.kmskeylink)

disk_not_encrypted(disk) if not disk.encryption.kmskeylink
