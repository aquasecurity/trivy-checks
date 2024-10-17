# METADATA
# title: Ensure that Cloud Storage bucket is not anonymously or publicly accessible.
# description: |
#   Using 'allUsers' or 'allAuthenticatedUsers' as members in an IAM member/binding causes data to be exposed outside of the organisation.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b
# custom:
#   id: AVD-GCP-0001
#   avd_id: AVD-GCP-0001
#   provider: google
#   service: storage
#   severity: HIGH
#   short_code: no-public-access
#   recommended_action: Restrict public access to the bucket.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket_iam#member/members
#     good_examples: checks/cloud/google/storage/no_public_access.yaml
#     bad_examples: checks/cloud/google/storage/no_public_access.yaml
package builtin.google.storage.google0001

import rego.v1

deny contains res if {
	some bucket in input.google.storage.buckets
	isManaged(bucket)
	some member in bucket.bindings[_].members
	is_member_external(member.value)
	res := result.new("Bucket allows public access.", member)
}

deny contains res if {
	some bucket in input.google.storage.buckets
	isManaged(bucket)
	some member in bucket.members
	is_member_external(member.member.value)
	res := result.new("Bucket allows public access.", member.member)
}

is_member_external(member) := member in {"allUsers", "allAuthenticatedUsers"}
