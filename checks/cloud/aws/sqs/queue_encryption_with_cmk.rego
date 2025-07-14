# METADATA
# title: SQS queue should be encrypted with a CMK.
# description: |
#   Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html
# custom:
#   id: AWS-0135
#   aliases:
#     - AVD-AWS-0135
#     - queue-encryption-use-cmk
#   long_id: aws-sqs-queue-encryption-use-cmk
#   provider: aws
#   service: sqs
#   severity: HIGH
#   recommended_action: Encrypt SQS Queue with a customer-managed key
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sqs
#             provider: aws
#   examples: checks/cloud/aws/sqs/queue_encryption_with_cmk.yaml
package builtin.aws.sqs.aws0135

import rego.v1

deny contains res if {
	some queue in input.aws.sqs.queues
	isManaged(queue)
	queue.encryption.kmskeyid.value == "alias/aws/sqs"
	res := result.new("Queue is not encrypted with a customer managed key.", queue.encryption.kmskeyid)
}
