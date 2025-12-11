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
#   aliases:
#     - aws-autoscaling-enable-at-rest-encryption
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
#   examples: checks/cloud/aws/ec2/as_enable_at_rest_encryption.yaml
package builtin.aws.ec2.aws0008

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cfg in input.aws.ec2.launchconfigurations
	cfg.rootblockdevice
	not cfg.rootblockdevice.encrypted.value
	res := result.new(
		"Root block device is not encrypted.",
		metadata.obj_by_path(cfg, ["rootblockdevice", "encrypted"]),
	)
}

deny contains res if {
	some cfg in input.aws.ec2.launchconfigurations
	some device in cfg.ebsblockdevices
	not device.encrypted.value
	res := result.new(
		"EBS block device is not encrypted.",
		metadata.obj_by_path(device, ["encrypted"]),
	)
}
