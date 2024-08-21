# METADATA
# title: Launch configuration with unencrypted block device.
# description: |
#   Block devices should be encrypted to ensure sensitive data is held securely at rest.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html
# custom:
#   id: AVD-AWS-0008
#   avd_id: AVD-AWS-0008
#   provider: aws
#   service: ec2
#   severity: HIGH
#   short_code: enable-launch-config-at-rest-encryption
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
#     good_examples: checks/cloud/aws/ec2/as_enable_at_rest_encryption.tf.go
#     bad_examples: checks/cloud/aws/ec2/as_enable_at_rest_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/ec2/as_enable_at_rest_encryption.cf.go
#     bad_examples: checks/cloud/aws/ec2/as_enable_at_rest_encryption.cf.go
package builtin.aws.ec2.aws0008

import rego.v1

deny contains res if {
	some cfg in input.aws.ec2.launchconfigurations
	cfg.rootblockdevice.encrypted.value == false
	res := result.new("Root block device is not encrypted.", cfg.rootblockdevice.encrypted)
}

deny contains res if {
	some cfg in input.aws.ec2.launchconfigurations
	some device in cfg.ebsblockdevices
	device.encrypted.value == false
	res := result.new("EBS block device is not encrypted.", device.encrypted.value)
}
