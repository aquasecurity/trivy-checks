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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#encrypted
#     good_examples: checks/cloud/aws/ec2/enable_volume_encryption.tf.go
#     bad_examples: checks/cloud/aws/ec2/enable_volume_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ec2/enable_volume_encryption.cf.go
#     bad_examples: checks/cloud/aws/ec2/enable_volume_encryption.cf.go
package builtin.aws.ec2.aws0026

import rego.v1

deny contains res if {
	some volume in input.aws.ec2.volumes
	volume.__defsec_metadata.managed
	volume.encryption.enabled.value == false
	res := result.new("EBS volume is not encrypted.", volume.encryption.enabled)
}
