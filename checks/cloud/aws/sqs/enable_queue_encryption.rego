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
#   id: AVD-AWS-0096
#   avd_id: AVD-AWS-0096
#   provider: aws
#   service: sqs
#   severity: HIGH
#   short_code: enable-queue-encryption
#   recommended_action: Turn on SQS Queue encryption
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sqs
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse
#     good_examples: checks/cloud/aws/sqs/enable_queue_encryption.tf.go
#     bad_examples: checks/cloud/aws/sqs/enable_queue_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/sqs/enable_queue_encryption.cf.go
#     bad_examples: checks/cloud/aws/sqs/enable_queue_encryption.cf.go
package builtin.aws.sqs.aws0096

import rego.v1

deny contains res if {
	some queue in input.aws.sqs.queues
	isManaged(queue)
	queue.encryption.kmskeyid.value == ""
	queue.encryption.managedencryption.value == false
	res := result.new("Queue is not encrypted", queue.encryption)
}
