# METADATA
# title: Unencrypted SNS topic.
# description: |
#   Topics should be encrypted to protect their contents.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html
# custom:
#   id: AVD-AWS-0095
#   avd_id: AVD-AWS-0095
#   provider: aws
#   service: sns
#   severity: HIGH
#   short_code: enable-topic-encryption
#   recommended_action: Turn on SNS Topic encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sns
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse
#     good_examples: checks/cloud/aws/sns/enable_topic_encryption.tf.go
#     bad_examples: checks/cloud/aws/sns/enable_topic_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/sns/enable_topic_encryption.cf.go
#     bad_examples: checks/cloud/aws/sns/enable_topic_encryption.cf.go
package builtin.aws.sns.aws0095

import rego.v1

deny contains res if {
	some topic in input.aws.sns.topics
	topic.encryption.kmskeyid.value == ""
	res := result.new(
		"Topic does not have encryption enabled.",
		topic.encryption.kmskeyid,
	)
}
