# METADATA
# title: Kinesis stream is unencrypted.
# description: |
#   Kinesis streams should be encrypted to ensure sensitive data is kept private. Additionally, non-default KMS keys should be used so granularity of access control can be ensured.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html
# custom:
#   id: AVD-AWS-0064
#   avd_id: AVD-AWS-0064
#   provider: aws
#   service: kinesis
#   severity: HIGH
#   short_code: enable-in-transit-encryption
#   recommended_action: Enable in transit encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: kinesis
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kinesis_stream#encryption_type
#     good_examples: checks/cloud/aws/kinesis/enable_in_transit_encryption.tf.go
#     bad_examples: checks/cloud/aws/kinesis/enable_in_transit_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/kinesis/enable_in_transit_encryption.cf.go
#     bad_examples: checks/cloud/aws/kinesis/enable_in_transit_encryption.cf.go
package builtin.aws.kinesis.aws0064

import rego.v1

deny contains res if {
	some stream in input.aws.kinesis.streams
	stream.encryption.type.value != "KMS"
	res := result.new("Stream does not use KMS encryption.", stream.encryption.type)
}

deny contains res if {
	some stream in input.aws.kinesis.streams
	stream.encryption.type.value == "KMS"
	stream.encryption.kmskeyid.value == ""
	res := result.new("Stream does not use a custom-managed KMS key.", stream.encryption.kmskeyid)
}
