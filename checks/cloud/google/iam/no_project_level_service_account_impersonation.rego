# METADATA
# title: Users should not be granted service account access at the project level
# description: |
#   Users with service account access at project level can impersonate any service account. Instead, they should be given access to particular service accounts as required.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/iam/docs/impersonating-service-accounts
# custom:
#   aliases:
#     - google-iam-no-project-level-service-account-impersonation
#   avd_id: AVD-GCP-0011
#   provider: google
#   service: iam
#   severity: MEDIUM
#   short_code: no-project-level-service-account-impersonation
#   recommended_action: Provide access at the service-level instead of project-level, if required
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   examples: checks/cloud/google/iam/no_project_level_service_account_impersonation.yaml
package builtin.google.iam.google0011

import rego.v1

import data.lib.google.iam

deny contains res if {
	some role in iam.roles("projects")
	iam.is_privileged_access_role(role.value)
	res := result.new("Service account access is granted to a user at project level.", role)
}
