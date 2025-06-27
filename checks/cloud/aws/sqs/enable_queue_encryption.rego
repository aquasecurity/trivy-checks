# METADATA
# title: Unencrypted SQS queue.
# description: |
#   Queues should be encrypted to protect queue contents.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html
# custom:
#   id: AWS-0096
#   aliases:
#     - AVD-AWS-0096
#     - enable-queue-encryption
#   long_id: aws-sqs-enable-queue-encryption
#   provider: aws
#   service: sqs
#   severity: HIGH
#   recommended_action: Turn on SQS Queue encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sqs
#             provider: aws
#   examples: checks/cloud/aws/sqs/enable_queue_encryption.yaml
package builtin.aws.sqs.aws0096

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some queue in input.aws.sqs.queues
	isManaged(queue)
	without_cmk(queue)
	not_encrypted(queue)
	res := result.new("Queue is not encrypted", queue.encryption)
}

without_cmk(queue) if value.is_empty(queue.encryption.kmskeyid)

without_cmk(queue) if not queue.encryption.kmskeyid

not_encrypted(queue) if value.is_false(queue.encryption.managedencryption)

not_encrypted(queue) if not queue.encryption.managedencryption
