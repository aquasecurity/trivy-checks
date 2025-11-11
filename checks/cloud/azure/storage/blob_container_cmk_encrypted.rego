# METADATA
# title: Storage account should use customer-managed keys for encryption
# description: |
#   Storage accounts should use customer-managed keys (CMK) for encryption to provide additional control over the encryption keys.
#   Customer-managed keys allow you to create, rotate, disable, and revoke access controls.
#   They also provide greater flexibility to audit the encryption keys that are used to protect your data.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview
# custom:
#   id: AZU-0060
#   avd_id: AVD-AZU-0060
#   aliases:
#     - AVD-AZU-0060
#     - blob-container-cmk-encrypted
#   provider: azure
#   service: storage
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   recommended_action: Configure customer-managed keys for storage account encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/blob_container_cmk_encrypted.yaml
package builtin.azure.storage.azure0060

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	count(account.containers) > 0
	lacks_customer_managed_keys(account)
	res := result.new(
		"Storage account with blob containers should use customer-managed keys for encryption.",
		metadata.obj_by_path(account, ["customermanagedkey"]),
	)
}

lacks_customer_managed_keys(account) if {
	not account.customermanagedkey
}

lacks_customer_managed_keys(account) if {
	account.customermanagedkey
	not account.customermanagedkey.keyvaultkeyid
}

lacks_customer_managed_keys(account) if {
	not isManaged(account.customermanagedkey.keyvaultkeyid)
}

lacks_customer_managed_keys(account) if {
	isManaged(account.customermanagedkey.keyvaultkeyid)
	value.is_empty(account.customermanagedkey.keyvaultkeyid)
}
