# METADATA
# title: Storage account should have logging enabled
# description: |
#   Storage Analytics logs detailed information about successful and failed requests to a storage service.
#   This information can be used to monitor individual requests and to diagnose issues with a storage service.
#   Logging should be enabled for at least one storage service type.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/common/storage-analytics-logging
# custom:
#   id: AZU-0057
#   long_id: azure-storage-storage-account-logging-enabled
#   aliases:
#     - AVD-AZU-0057
#     - storage-account-logging-enabled
#     - azure-storage-storage-account-logging-enabled
#   provider: azure
#   service: storage
#   severity: MEDIUM
#   minimum_trivy_version: 0.75.0
#   recommended_action: Enable logging for at least one storage service (Queue, Table, or Blob)
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/storage_account_logging_enabled.yaml
package builtin.azure.storage.azure0057

import rego.v1

import data.lib.cloud.value

import data.lib.cloud.metadata

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	logging_disabled(account)
	res := result.new(
		"Storage account does not have logging enabled for any service.",
		logging_metadata(account),
	)
}

logging_metadata(account) := metadata.obj_by_path(account, ["diagnosticloggingenabled"]) if object.get(account, "diagnosticloggingenabled", null) != null

logging_metadata(account) := metadata.obj_by_path(account, ["queueproperties", "enablelogging"]) if not account.diagnosticloggingenabled

logging_disabled(account) if {
	diagnostic_logging_disabled(account)
	not account.queueproperties
}

logging_disabled(account) if {
	diagnostic_logging_disabled(account)
	value.is_false(account.queueproperties.enablelogging)
}

diagnostic_logging_disabled(account) if not account.diagnosticloggingenabled

diagnostic_logging_disabled(account) if value.is_false(account.diagnosticloggingenabled)
