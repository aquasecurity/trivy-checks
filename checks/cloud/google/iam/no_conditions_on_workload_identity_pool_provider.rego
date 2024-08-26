# METADATA
# title: A configuration for an external workload identity pool provider should have conditions set
# description: |
#   In GitHub Actions, one can authenticate to Google Cloud by setting values for workload_identity_provider and service_account and requesting a short-lived OIDC token which is then used to execute commands as that Service Account. If you don't specify a condition in the workload identity provider pool configuration, then any GitHub Action can assume this role and act as that Service Account.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.revblock.dev/exploiting-misconfigured-google-cloud-service-accounts-from-github-actions/
# custom:
#   id: AVD-GCP-0068
#   avd_id: AVD-GCP-0068
#   provider: google
#   service: iam
#   severity: HIGH
#   short_code: no-conditions-workload-identity-pool-provider
#   recommended_action: Set conditions on this provider, for example by restricting it to only be allowed from repositories in your GitHub organization
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/iam_workload_identity_pool_provider#attribute_condition
#     good_examples: checks/cloud/google/iam/no_conditions_on_workload_identity_pool_provider.tf.go
#     bad_examples: checks/cloud/google/iam/no_conditions_on_workload_identity_pool_provider.tf.go
package builtin.google.iam.google0068

import rego.v1

deny contains res if {
	some provider in input.google.iam.workloadidentitypoolproviders
	not has_conditions(provider)
	res := result.new(
		"This workload identity pool provider configuration has no conditions set.",
		object.get(provider, "attributecondition", provider),
	)
}

has_conditions(provider) := provider.attributecondition.value != ""
