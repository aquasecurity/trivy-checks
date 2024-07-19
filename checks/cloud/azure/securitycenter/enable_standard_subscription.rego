# METADATA
# title: Enable the standard security center subscription tier
# description: |
#   To benefit from Azure Defender you should use the Standard subscription tier.
#
#   Enabling Azure Defender extends the capabilities of the free mode to workloads running in private and other public clouds, providing unified security management and threat protection across your hybrid cloud workloads.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/security-center/security-center-pricing
# custom:
#   id: AVD-AZU-0045
#   avd_id: AVD-AZU-0045
#   provider: azure
#   service: security-center
#   severity: LOW
#   short_code: enable-standard-subscription
#   recommended_action: Enable standard subscription tier to benefit from Azure Defender
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: securitycenter
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#tier
#     good_examples: checks/cloud/azure/securitycenter/enable_standard_subscription.tf.go
#     bad_examples: checks/cloud/azure/securitycenter/enable_standard_subscription.tf.go
package builtin.azure.securitycenter.azure0045

import rego.v1

free_tier := "Free"

deny contains res if {
	some sub in input.azure.securitycenter.subscriptions
	isManaged(sub)

	sub.tier.value == free_tier
	res := result.new(
		"Security center subscription uses the free tier.",
		sub.tier,
	)
}
