# METADATA
# title: Cloud Storage Bucket Versioning Disabled
# description: |
#   Object versioning in Cloud Storage is recommended to protect against accidental or malicious deletions.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#enabled
# custom:
#   id: GCP-0078
#   aliases:
#     - storage-bucket-versioning-disabled
#     - AVD-GCP-0078
#   long_id: google-storage-enable-bucket-versioning
#   provider: google
#   service: storage
#   severity: MEDIUM
#   minimum_trivy_version: 0.65.0
#   recommended_action: |
#     Enable object versioning on Cloud Storage buckets to preserve older versions of objects. In Terraform, set `versioning { enabled = true }` for the bucket resource.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: google
#   examples: checks/cloud/google/storage/enable_bucket_versioning.yaml
package builtin.google.storage.google0078

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some bucket in input.google.storage.buckets
	not bucket.versioning.enabled.value

	res := result.new(
		"Storage bucket versioning is not enabled.",
		metadata.obj_by_path(bucket, ["versioning", "enabled"]),
	)
}
