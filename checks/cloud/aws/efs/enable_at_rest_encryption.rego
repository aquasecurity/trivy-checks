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
#   id: AVD-AWS-0037
#   avd_id: AVD-AWS-0037
#   provider: aws
#   service: efs
#   severity: HIGH
#   short_code: enable-at-rest-encryption
#   recommended_action: Enable encryption for EFS
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: efs
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system
#     good_examples: checks/cloud/aws/efs/enable_at_rest_encryption.yaml
#     bad_examples: checks/cloud/aws/efs/enable_at_rest_encryption.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/efs/enable_at_rest_encryption.yaml
#     bad_examples: checks/cloud/aws/efs/enable_at_rest_encryption.yaml
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
