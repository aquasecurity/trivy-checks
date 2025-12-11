# METADATA
# title: Storage account should have blob soft delete enabled
# description: |
#   Blob soft delete protects blob data from being accidentally or erroneously modified or deleted.
#   When blob soft delete is enabled, deleted blobs are retained in the system for a specified retention period.
#   During the retention period, you can restore a soft-deleted blob to its state at the time it was deleted.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview
# custom:
#   id: AZU-0056
#   long_id: azure-storage-blobs-soft-deletion-enabled
#   aliases:
#     - AVD-AZU-0056
#     - blobs-soft-deletion-enabled
#   provider: azure
#   service: storage
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   recommended_action: Enable soft delete for blobs with an appropriate retention period
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/blobs_soft_deletion_enabled.yaml
package builtin.azure.storage.azure0056

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	blob_soft_delete_disabled(account)
	res := result.new(
		"Storage account does not have blob soft delete enabled.",
		metadata.obj_by_path(account, ["blobproperties", "deleteretentionpolicy", "days"]),
	)
}

blob_soft_delete_disabled(account) if {
	value.is_equal(account.blobproperties.deleteretentionpolicy.days, 0)
}
