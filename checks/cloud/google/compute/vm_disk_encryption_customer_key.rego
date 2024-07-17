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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#kms_key_self_link
#     good_examples: checks/cloud/google/compute/vm_disk_encryption_customer_key.tf.go
#     bad_examples: checks/cloud/google/compute/vm_disk_encryption_customer_key.tf.go
package builtin.google.compute.google0033

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	disks := array.concat(
		object.get(instance, "bootdisks", []),
		object.get(instance, "attacheddisks", []),
	)

	some disk in disks

	not disk_is_encrypted(disk)
	res := result.new(
		"Instance disk encryption does not use a customer managed key.",
		object.get(disk, ["encryption", "kmskeylink"], disk),
	)
}

disk_is_encrypted(disk) := disk.encryption.kmskeylink.value != ""
