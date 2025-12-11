# METADATA
# title: Storage account should have infrastructure encryption enabled
# description: |
#   Infrastructure encryption provides an additional layer of encryption at the infrastructure level.
#   When infrastructure encryption is enabled, data in the storage account is encrypted twice -
#   once at the service level and once at the infrastructure level with two different encryption algorithms.
#   This provides double encryption for enhanced security.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/common/infrastructure-encryption-enable
# custom:
#   id: AZU-0061
#   long_id: azure-storage-infrastructure-encryption-enabled
#   aliases:
#     - AVD-AZU-0061
#     - infrastructure-encryption-enabled
#   provider: azure
#   service: storage
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   recommended_action: Enable infrastructure encryption for storage account
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/infrastructure_encryption_enabled.yaml
package builtin.azure.storage.azure0061

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	infrastructure_encryption_disabled(account)
	res := result.new(
		"Storage account does not have infrastructure encryption enabled.",
		metadata.obj_by_path(account, ["infrastructureencryptionenabled"]),
	)
}

infrastructure_encryption_disabled(account) if {
	not account.infrastructureencryptionenabled
}

infrastructure_encryption_disabled(account) if {
	value.is_false(account.infrastructureencryptionenabled)
}
