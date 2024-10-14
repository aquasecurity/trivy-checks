# METADATA
# title: AWS SQS policy document has wildcard action statement.
# description: |
#   SQS Policy actions should always be restricted to a specific set.
#   This ensures that the queue itself cannot be modified or deleted, and prevents possible future additions to queue actions to be implicitly allowed.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html
# custom:
#   id: AVD-AWS-0097
#   avd_id: AVD-AWS-0097
#   provider: aws
#   service: sqs
#   severity: HIGH
#   short_code: no-wildcards-in-policy-documents
#   recommended_action: Keep policy scope to the minimum that is required to be effective
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sqs
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy
#     good_examples: checks/cloud/aws/sqs/no_wildcards_in_policy_documents.yaml
#     bad_examples: checks/cloud/aws/sqs/no_wildcards_in_policy_documents.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/sqs/no_wildcards_in_policy_documents.yaml
#     bad_examples: checks/cloud/aws/sqs/no_wildcards_in_policy_documents.yaml
package builtin.aws.sqs.aws0097

import rego.v1

deny contains res if {
	some queue in input.aws.sqs.queues
	some policy_doc in queue.policies
	doc := json.unmarshal(policy_doc.document.value)
	some statement in doc.Statement
	statement.Effect == "Allow"
	some action in statement.Action
	action in ["*", "sqs:*"]
	res := result.new("Queue policy does not restrict actions to a known set.", policy_doc.document)
}
