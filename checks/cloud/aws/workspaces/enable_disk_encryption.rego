# METADATA
# title: Root and user volumes on Workspaces should be encrypted
# description: |
#   Workspace volumes for both user and root should be encrypted to protect the data stored on them.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html
# custom:
#   id: AWS-0109
#   aliases:
#     - AVD-AWS-0109
#     - enable-disk-encryption
#   long_id: aws-workspaces-enable-disk-encryption
#   provider: aws
#   service: workspaces
#   severity: HIGH
#   recommended_action: Root and user volume encryption should be enabled
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: workspaces
#             provider: aws
#   examples: checks/cloud/aws/workspaces/enable_disk_encryption.yaml
package builtin.aws.workspaces.aws0109

import rego.v1

deny contains res if {
	some workspace in input.aws.workspaces.workspaces
	workspace.rootvolume.encryption.enabled.value == false
	res := result.new("Root volume does not have encryption enabled.", workspace.rootvolume.encryption)
}

deny contains res if {
	some workspace in input.aws.workspaces.workspaces
	workspace.uservolume.encryption.enabled.value == false
	res := result.new("User volume does not have encryption enabled.", workspace.uservolume.encryption)
}
