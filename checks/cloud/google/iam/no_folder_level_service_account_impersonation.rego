# METADATA
# title: Users should not be granted service account access at the folder level
# description: |
#   Users with service account access at folder level can impersonate any service account. Instead, they should be given access to particular service accounts as required.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/iam/docs/impersonating-service-accounts
# custom:
#   id: GCP-0005
#   aliases:
#     - AVD-GCP-0005
#     - no-folder-level-service-account-impersonation
#   long_id: google-iam-no-folder-level-service-account-impersonation
#   provider: google
#   service: iam
#   severity: MEDIUM
#   recommended_action: Provide access at the service-level instead of folder-level, if required
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   examples: checks/cloud/google/iam/no_folder_level_service_account_impersonation.yaml
package builtin.google.IAM.google0005

import rego.v1

import data.lib.google.iam

deny contains res if {
	some role in iam.roles("folders")
	iam.is_privileged_access_role(role.value)
	res := result.new("Service account access is granted to a user at project level.", role)
}
