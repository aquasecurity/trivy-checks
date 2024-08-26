# METADATA
# title: Cloud Storage buckets should be encrypted with a customer-managed key.
# description: |
#   Using unmanaged keys makes rotation and general management difficult.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/storage/docs/encryption/customer-managed-keys
# custom:
#   id: AVD-GCP-0066
#   avd_id: AVD-GCP-0066
#   provider: google
#   service: storage
#   severity: LOW
#   short_code: bucket-encryption-customer-key
#   recommended_action: Encrypt Cloud Storage buckets using customer-managed keys.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#encryption
#     good_examples: checks/cloud/google/storage/bucket_encryption_customer_key.tf.go
#     bad_examples: checks/cloud/google/storage/bucket_encryption_customer_key.tf.go
package builtin.google.storage.google0066

import rego.v1

deny contains res if {
	some bucket in input.google.storage.buckets
	bucket.__defsec_metadata.managed
	bucket.encryption.defaultkmskeyname.value == ""
	res := result.new("Storage bucket encryption does not use a customer-managed key.", bucket.encryption.defaultkmskeyname)
}
