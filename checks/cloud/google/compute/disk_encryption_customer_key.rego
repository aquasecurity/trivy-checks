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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link
#     good_examples: checks/cloud/google/compute/disk_encryption_customer_key.tf.go
#     bad_examples: checks/cloud/google/compute/disk_encryption_customer_key.tf.go
package builtin.google.compute.google0034

import rego.v1

deny contains res if {
	some disk in input.google.compute.disks
	not is_disk_encrypted(disk)
	res := result.new(
		"Disk is not encrypted with a customer managed key.",
		object.get(disk, ["encryption", "kmskeylink"], disk),
	)
}

is_disk_encrypted(disk) := disk.encryption.kmskeylink.value != ""
