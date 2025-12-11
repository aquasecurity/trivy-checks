# METADATA
# title: The minimum TLS version for Storage Accounts should be TLS1_2 or higher
# description: |
#   Azure Storage supports four versions of the TLS protocol: 1.0, 1.1, 1.2, and 1.3.
#   Azure Storage uses TLS 1.2 or TLS 1.3 on public HTTPS endpoints, while TLS 1.0 and TLS 1.1 are still supported for backward compatibility.
#   This check will warn if the minimum TLS version is set lower than TLS1_2. TLS1_2 and TLS1_3 are both allowed.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version
# custom:
#   id: AZU-0011
#   long_id: azure-storage-use-secure-tls-policy
#   aliases:
#     - AVD-AZU-0011
#     - use-secure-tls-policy
#   provider: azure
#   service: storage
#   severity: CRITICAL
#   recommended_action: Use a more recent TLS version for the storage account
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/use_secure_tls_policy.yaml
package builtin.azure.storage.azure0011

import rego.v1

import data.lib.cloud.value

allowed_tls_versions := {"TLS1_2", "TLS1_3"}

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	non_compliant_tls(account)
	res := result.new(
		"Storage account uses an insecure TLS version.",
		object.get(account, "minimumtlsversion", account),
	)
}

non_compliant_tls(account) if not account.minimumtlsversion

non_compliant_tls(account) if {
	value.is_known(account.minimumtlsversion)
	not account.minimumtlsversion.value in allowed_tls_versions
}
