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
#   id: AWS-0064
#   aliases:
#     - AVD-AWS-0064
#     - enable-in-transit-encryption
#   long_id: aws-kinesis-enable-in-transit-encryption
#   provider: aws
#   service: kinesis
#   severity: HIGH
#   recommended_action: Enable in transit encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: kinesis
#             provider: aws
#   examples: checks/cloud/aws/kinesis/enable_in_transit_encryption.yaml
package builtin.aws.kinesis.aws0064

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some stream in input.aws.kinesis.streams
	encryption_is_not_kms(stream)
	res := result.new(
		"Stream does not use KMS encryption.",
		metadata.obj_by_path(stream, ["encryption", "type"]),
	)
}

encryption_is_not_kms(stream) if value.is_not_equal(stream.encryption.type, "KMS")

encryption_is_not_kms(stream) if not stream.encryption.type

deny contains res if {
	some stream in input.aws.kinesis.streams
	stream.encryption.type.value == "KMS"
	without_cmk(stream)
	res := result.new(
		"Stream does not use a custom-managed KMS key.",
		metadata.obj_by_path(stream, ["encryption", "kmskeyid"]),
	)
}

without_cmk(stream) if value.is_empty(stream.encryption.kmskeyid)

without_cmk(stream) if not stream.encryption.kmskeyid
