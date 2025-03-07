# METADATA
# title: EBS volumes must be encrypted
# description: |
#   By enabling encryption on EBS volumes you protect the volume, the disk I/O and any derived snapshots from compromise if intercepted.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
# custom:
#   id: AVD-AWS-0026
#   avd_id: AVD-AWS-0026
#   aliases:
#     - aws-ebs-enable-volume-encryption
#   provider: aws
#   service: ec2
#   severity: HIGH
#   short_code: enable-volume-encryption
#   recommended_action: Enable encryption of EBS volumes
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   examples: checks/cloud/aws/ec2/enable_volume_encryption.yaml
package builtin.aws.ec2.aws0026

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some volume in input.aws.ec2.volumes
	isManaged(volume)
	not volume.encryption.enabled.value
	res := result.new(
		"EBS volume is not encrypted.",
		metadata.obj_by_path(volume, ["encryption", "enabled"]),
	)
}
