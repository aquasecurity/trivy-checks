# METADATA
# title: The encryption key used to encrypt a compute disk has been specified in plaintext.
# description: |
#   Sensitive values such as raw encryption keys should not be included in your Terraform code, and should be stored securely by a secrets manager.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/compute/docs/disks/customer-supplied-encryption
# custom:
#   id: AVD-GCP-0037
#   avd_id: AVD-GCP-0037
#   provider: google
#   service: compute
#   severity: CRITICAL
#   short_code: disk-encryption-no-plaintext-key
#   recommended_action: Reference a managed key rather than include the key in raw format.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link
#     good_examples: checks/cloud/google/compute/disk_encryption_no_plaintext_key.yaml
#     bad_examples: checks/cloud/google/compute/disk_encryption_no_plaintext_key.yaml
package builtin.google.compute.google0037

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	disks := array.concat(
		object.get(instance, "bootdisks", []),
		object.get(instance, "attacheddisks", []),
	)

	some disk in disks
	encryption_key_has_plaintext(disk)
	res := result.new(
		"Instance disk has encryption key provided in plaintext.",
		disk.encryption.rawkey,
	)
}

deny contains res if {
	some disk in input.google.compute.disks
	encryption_key_has_plaintext(disk)
	res := result.new(
		"Disk encryption key is supplied in plaintext.",
		disk.encryption.rawkey,
	)
}

encryption_key_has_plaintext(disk) := count(disk.encryption.rawkey.value) > 0
