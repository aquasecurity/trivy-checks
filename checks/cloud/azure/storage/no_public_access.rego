# METADATA
# title: Storage containers in blob storage mode should not have public access
# description: |
#   Storage container public access should be off. It can be configured for blobs only, containers and blobs or off entirely. The default is off, with no public access.
#   Explicitly overriding publicAccess to anything other than off should be avoided.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal#set-the-public-access-level-for-a-container
# custom:
#   id: AVD-AZU-0007
#   avd_id: AVD-AZU-0007
#   provider: azure
#   service: storage
#   severity: HIGH
#   short_code: no-public-access
#   recommended_action: Disable public access to storage containers
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   terraform:
#     links:
#       - https://www.terraform.io/docs/providers/azure/r/storage_container.html#properties
#     good_examples: checks/cloud/azure/storage/no_public_access.tf.go
#     bad_examples: checks/cloud/azure/storage/no_public_access.tf.go
package builtin.azure.storage.azure0007

import rego.v1

deny contains res if {
	some account in input.azure.storage.accounts
	some container in account.containers
	container.publicaccess.value != "off"

	res := result.new(
		"Container allows public access.",
		container.publicaccess,
	)
}
