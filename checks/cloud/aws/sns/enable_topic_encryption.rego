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
#     good_examples: checks/cloud/aws/sns/enable_topic_encryption.yaml
#     bad_examples: checks/cloud/aws/sns/enable_topic_encryption.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/sns/enable_topic_encryption.yaml
#     bad_examples: checks/cloud/aws/sns/enable_topic_encryption.yaml
package builtin.aws.sns.aws0095

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some topic in input.aws.sns.topics
	not_encrypted(topic)
	res := result.new(
		"Topic does not have encryption enabled.",
		metadata.obj_by_path(topic, ["encryption", "kmskeyid"]),
	)
}

not_encrypted(topic) if value.is_empty(topic.encryption.kmskeyid)

not_encrypted(topic) if not topic.encryption.kmskeyid
