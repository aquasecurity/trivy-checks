# METADATA
# title: Cloud Storage Bucket Logging Not Enabled
# description: |
#   Cloud Storage bucket access logs should be enabled for audit purposes.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#log_bucket
# custom:
#   id: GCP-0077
#   aliases:
#     - storage-bucket-logging-not-enabled
#     - AVD-GCP-0077
#   long_id: google-storage-enable-bucket-logging
#   provider: google
#   service: storage
#   severity: MEDIUM
#   minimum_trivy_version: 0.66.0
#   recommended_action: |
#     Enable Access and Storage logs for Cloud Storage buckets by configuring a log sink or specifying a `log_bucket` in Terraform.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: google
#   examples: checks/cloud/google/storage/enable_bucket_logging.yaml
package builtin.google.storage.google0077

import rego.v1

import data.lib.cloud.metadata

buckets_for_logging := {name |
	some bucket in input.google.storage.buckets
	name := bucket.logging.logbucket.value
}

deny contains res if {
	some bucket in input.google.storage.buckets
	not bucket.name.value in buckets_for_logging
	not has_logging(bucket)

	res := result.new(
		"Storage bucket logging is not configured with a target log bucket.",
		metadata.obj_by_path(bucket, ["logging", "logbucket"]),
	)
}

has_logging(bucket) if bucket.logging.logbucket.value != ""
