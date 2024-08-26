# METADATA
# title: Users should not be granted service account access at the organization level
# description: |
#   Users with service account access at organization level can impersonate any service account. Instead, they should be given access to particular service accounts as required.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/iam/docs/impersonating-service-accounts
# custom:
#   id: AVD-GCP-0009
#   avd_id: AVD-GCP-0009
#   provider: google
#   service: iam
#   severity: MEDIUM
#   short_code: no-org-level-service-account-impersonation
#   recommended_action: Provide access at the service-level instead of organization-level, if required
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam
#     good_examples: checks/cloud/google/iam/no_org_level_service_account_impersonation.tf.go
#     bad_examples: checks/cloud/google/iam/no_org_level_service_account_impersonation.tf.go
package builtin.google.iam.google0009

import rego.v1

import data.lib.google.iam

deny contains res if {
	some role in iam.roles("organizations")
	iam.is_privileged_access_role(role.value)
	res := result.new("Service account access is granted to a user at project level.", role)
}
