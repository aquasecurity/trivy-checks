# METADATA
# title: EFS Encryption has not been enabled
# description: |
#   If your organization is subject to corporate or regulatory policies that require encryption of data and metadata at rest, we recommend creating a file system that is encrypted at rest, and mounting your file system using encryption of data in transit.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/efs/latest/ug/encryption.html
# custom:
#   id: AWS-0037
#   aliases:
#     - AVD-AWS-0037
#     - enable-at-rest-encryption
#   long_id: aws-efs-enable-at-rest-encryption
#   provider: aws
#   service: efs
#   severity: HIGH
#   recommended_action: Enable encryption for EFS
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: efs
#             provider: aws
#   examples: checks/cloud/aws/efs/enable_at_rest_encryption.yaml
package builtin.aws.efs.aws0037

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some fs in input.aws.efs.filesystems
	not fs.encrypted.value
	res := result.new(
		"File system is not encrypted.",
		metadata.obj_by_path(fs, ["encrypted"]),
	)
}
