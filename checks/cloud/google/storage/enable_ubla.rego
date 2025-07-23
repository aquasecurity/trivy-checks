# METADATA
# title: Ensure that Cloud Storage buckets have uniform bucket-level access enabled
# description: |
#   When you enable uniform bucket-level access on a bucket, Access Control Lists (ACLs) are disabled, and only bucket-level Identity and Access Management (IAM) permissions grant access to that bucket and the objects it contains. You revoke all access granted by object ACLs and the ability to administrate permissions using bucket ACLs.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/storage/docs/uniform-bucket-level-access
#   - https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b
# custom:
#   id: AVD-GCP-0002
#   avd_id: AVD-GCP-0002
#   provider: google
#   service: storage
#   severity: MEDIUM
#   short_code: enable-ubla
#   recommended_action: Enable uniform bucket level access to provide a uniform permissioning system.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: google
#   examples: checks/cloud/google/storage/enable_ubla.yaml
package builtin.google.storage.google0002

import rego.v1

deny contains res if {
	some bucket in input.google.storage.buckets
	isManaged(bucket)
	bucket.enableuniformbucketlevelaccess.value == false
	res := result.new("Bucket has uniform bucket level access disabled.", bucket.enableuniformbucketlevelaccess)
}
