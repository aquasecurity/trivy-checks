# METADATA
# title: Storage account should have secure transfer and minimum TLS version configured
# description: |
#   Storage accounts should enforce HTTPS for secure data transfer and use a minimum TLS version of 1.2.
#   This ensures that logs and data stored in the storage account are encrypted in transit.
#   Azure Storage encrypts all data at rest by default, but transport encryption is also critical.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer
# custom:
#   id: AZU-0059
#   long_id: azure-storage-log-storage-encryption
#   aliases:
#     - AVD-AZU-0059
#     - log-storage-encryption
#   provider: azure
#   service: storage
#   severity: HIGH
#   minimum_trivy_version: 0.68.0
#   recommended_action: Enable secure transfer and set minimum TLS version to TLS1_2
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/log_storage_encryption.yaml
package builtin.azure.storage.azure0059

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	https_not_enforced(account)
	res := result.new(
		"Storage account does not enforce HTTPS for secure transfer.",
		metadata.obj_by_path(account, ["enforcehttps"]),
	)
}

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	insecure_tls_version(account)
	res := result.new(
		"Storage account does not use a secure TLS version.",
		metadata.obj_by_path(account, ["minimumtlsversion"]),
	)
}

https_not_enforced(account) if not account.enforcehttps

https_not_enforced(account) if value.is_false(account.enforcehttps)

insecure_tls_version(account) if not account.minimumtlsversion

insecure_tls_version(account) if value.is_not_equal(account.minimumtlsversion, "TLS1_2")
