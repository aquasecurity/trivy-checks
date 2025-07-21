#  METADATA
#  title: Cloud Storage Bucket Logging Not Enabled
#  description: |
#    Cloud Storage bucket access logs should be enabled for audit purposes.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#log_bucket
# custom:
#   id: GCP-0077
#   aliases:
#     - google-storage-cloud-storage-bucket-logging-not-enabled
#     - AVD-GCP-0077
#   long_id: google-compute-enable-bucket-logging
#   provider: google
#   service: storage
#   severity: MEDIUM
#   recommended_action: |
#     Enable Access and Storage logs for Cloud Storage buckets by configuring a log sink or specifying a `log_bucket` in Terraform.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: google
#   examples: checks/cloud/google/storage/enable_bucket_logging.yaml
package builtin.google.compute.google0077

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some bucket in input.google.storage.buckets
	not bucket.logging.log_bucket

	res := result.new(
		"Storage bucket logging is not configured with a target log bucket.",
		metadata.obj_by_path(bucket, ["logging" , "log_bucket"]),
	)
}