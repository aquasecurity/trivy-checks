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
#   id: AZU-0045
#   aliases:
#     - AVD-AZU-0045
#     - enable-standard-subscription
#   long_id: azure-securitycenter-enable-standard-subscription
#   provider: azure
#   service: security-center
#   severity: LOW
#   recommended_action: Enable standard subscription tier to benefit from Azure Defender
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: securitycenter
#             provider: azure
#   examples: checks/cloud/azure/securitycenter/enable_standard_subscription.yaml
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
