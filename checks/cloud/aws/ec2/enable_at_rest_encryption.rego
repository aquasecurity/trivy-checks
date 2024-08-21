# METADATA
# title: Instance with unencrypted block device.
# description: |
#   Block devices should be encrypted to ensure sensitive data is held securely at rest.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html
# custom:
#   id: AVD-AWS-0131
#   avd_id: AVD-AWS-0131
#   provider: aws
#   service: ec2
#   severity: HIGH
#   short_code: enable-at-rest-encryption
#   recommended_action: Turn on encryption for all block devices
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices
#     good_examples: checks/cloud/aws/ec2/enable_at_rest_encryption.tf.go
#     bad_examples: checks/cloud/aws/ec2/enable_at_rest_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ec2/enable_at_rest_encryption.cf.go
#     bad_examples: checks/cloud/aws/ec2/enable_at_rest_encryption.cf.go
package builtin.aws.ec2.aws0131

import rego.v1

deny contains res if {
	some instance in input.aws.ec2.instances
	instance.rootblockdevice.encrypted.value == false
	res := result.new("Root block device is not encrypted.", instance.rootblockdevice.encrypted)
}

deny contains res if {
	some instance in input.aws.ec2.instances
	some ebs in instance.ebsblockdevices
	ebs.encrypted.value == false
	res := result.new("EBS block device is not encrypted.", ebs.encrypted)
}
