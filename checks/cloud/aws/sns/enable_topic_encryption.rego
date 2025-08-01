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
#   id: AWS-0095
#   aliases:
#     - AVD-AWS-0095
#     - enable-topic-encryption
#   long_id: aws-sns-enable-topic-encryption
#   provider: aws
#   service: sns
#   severity: HIGH
#   recommended_action: Turn on SNS Topic encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sns
#             provider: aws
#   examples: checks/cloud/aws/sns/enable_topic_encryption.yaml
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
