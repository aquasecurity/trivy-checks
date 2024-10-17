# METADATA
# title: The minimum TLS version for Storage Accounts should be TLS1_2
# description: |
#   Azure Storage currently supports three versions of the TLS protocol: 1.0, 1.1, and 1.2.
#   Azure Storage uses TLS 1.2 on public HTTPS endpoints, but TLS 1.0 and TLS 1.1 are still supported for backward compatibility.
#   This check will warn if the minimum TLS is not set to TLS1_2.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version
# custom:
#   id: AVD-AZU-0011
#   avd_id: AVD-AZU-0011
#   provider: azure
#   service: storage
#   severity: CRITICAL
#   short_code: use-secure-tls-policy
#   recommended_action: Use a more recent TLS/SSL policy for the load balancer
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version
#     good_examples: checks/cloud/azure/storage/use_secure_tls_policy.yaml
#     bad_examples: checks/cloud/azure/storage/use_secure_tls_policy.yaml
package builtin.azure.storage.azure0011

import rego.v1

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	not has_tls_1_2(account)
	res := result.new(
		"Storage account uses an insecure TLS version.",
		object.get(account, "minimumtlsversion", account),
	)
}

has_tls_1_2(account) := account.minimumtlsversion.value == "TLS1_2"
