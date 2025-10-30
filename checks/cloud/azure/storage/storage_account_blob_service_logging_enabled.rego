# METADATA
# title: Storage account blob service should have logging enabled
# description: |
#   Blob service logging captures detailed information about read, write, and delete operations.
#   This check ensures that diagnostic settings are configured for blob service logging.
#   Note: Blob service logging is configured via Azure Monitor diagnostic settings, not directly in storage account properties.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage
# custom:
#   id: AZU-0058
#   aliases:
#     - AVD-AZU-0058
#     - storage-account-blob-service-logging-enabled
#   long_id: azure-storage-storage-account-blob-service-logging-enabled
#   provider: azure
#   service: storage
#   severity: MEDIUM
#   recommended_action: Configure diagnostic settings to enable blob service logging
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/storage_account_blob_service_logging_enabled.yaml
package builtin.azure.storage.azure0058

import rego.v1

import data.lib.cloud.metadata

# This check requires diagnostic settings configuration which is not part of the storage account resource
deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	count(account.containers) > 0
	not has_blob_logging_configured(account)
	res := result.new(
		"Storage account with blob containers should have diagnostic settings configured for blob service logging.",
		account,
	)
}

# This function would need to check for diagnostic settings, which requires additional schema support
has_blob_logging_configured(account) if {
	# For now, this will always be false since diagnostic settings are not part of the storage account schema
	# In a complete implementation, this would check:
	# - azurerm_monitor_diagnostic_setting resource with storage account as target
	# - enabled logs for "StorageRead", "StorageWrite", "StorageDelete" categories
	false
}
