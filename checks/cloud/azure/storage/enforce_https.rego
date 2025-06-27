# METADATA
# title: Storage accounts should be configured to only accept transfers that are over secure connections
# description: |
#   You can configure your storage account to accept requests from secure connections only by setting the Secure transfer required property for the storage account.
#   When you require secure transfer, any requests originating from an insecure connection are rejected.
#   Microsoft recommends that you always require secure transfer for all of your storage accounts.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer
# custom:
#   id: AZU-0008
#   aliases:
#     - AVD-AZU-0008
#     - enforce-https
#   long_id: azure-storage-enforce-https
#   provider: azure
#   service: storage
#   severity: HIGH
#   recommended_action: Only allow secure connection for transferring data into storage accounts
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/enforce_https.yaml
package builtin.azure.storage.azure0008

import rego.v1

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	not account.enforcehttps.value
	res := result.new(
		"Account does not enforce HTTPS.",
		object.get(account, "enforcehttps", account),
	)
}
