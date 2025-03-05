# METADATA
# title: When using Queue Services for a storage account, logging should be enabled.
# description: |
#   Storage Analytics logs detailed information about successful and failed requests to a storage service.
#   This information can be used to monitor individual requests and to diagnose issues with a storage service.
#   Requests are logged on a best-effort basis.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/common/storage-analytics-logging?tabs=dotnet
# custom:
#   id: AVD-AZU-0009
#   avd_id: AVD-AZU-0009
#   provider: azure
#   service: storage
#   severity: MEDIUM
#   short_code: queue-services-logging-enabled
#   recommended_action: Enable logging for Queue Services
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/queue_services_logging_enabled.yaml
package builtin.azure.storage.azure0009

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	count(account.queues) > 0
	not account.queueproperties.enablelogging.value
	res := result.new(
		"Queue services storage account does not have logging enabled.",
		metadata.obj_by_path(account, ["queueproperties", "enablelogging"]),
	)
}
