# METADATA
# title: SNS topic not encrypted with CMK.
# description: |
#   Topics should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular key management.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html
# custom:
#   id: AWS-0136
#   aliases:
#     - AVD-AWS-0136
#     - topic-encryption-use-cmk
#   long_id: aws-sns-topic-encryption-use-cmk
#   provider: aws
#   service: sns
#   severity: HIGH
#   recommended_action: Use a CMK for SNS Topic encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sns
#             provider: aws
#   examples: checks/cloud/aws/sns/topic_encryption_with_cmk.yaml
package builtin.aws.sns.aws0136

import rego.v1

default_kms_key := "alias/aws/sns"

deny contains res if {
	some topic in input.aws.sns.topics
	topic.encryption.kmskeyid.value == default_kms_key
	res := result.new(
		"Topic encryption does not use a customer managed key.",
		topic.encryption.kmskeyid,
	)
}
