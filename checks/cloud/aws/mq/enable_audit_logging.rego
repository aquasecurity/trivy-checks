# METADATA
# title: MQ Broker should have audit logging enabled
# description: |
#   Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html
# custom:
#   id: AVD-AWS-0070
#   avd_id: AVD-AWS-0070
#   provider: aws
#   service: mq
#   severity: MEDIUM
#   short_code: enable-audit-logging
#   recommended_action: Enable audit logging
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: mq
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker#audit
#     good_examples: checks/cloud/aws/mq/enable_audit_logging.tf.go
#     bad_examples: checks/cloud/aws/mq/enable_audit_logging.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/mq/enable_audit_logging.cf.go
#     bad_examples: checks/cloud/aws/mq/enable_audit_logging.cf.go
package builtin.aws.mq.aws0070

import rego.v1

deny contains res if {
	some broker in input.aws.mq.brokers
	broker.logging.audit.value == false

	res := result.new("Broker does not have audit logging enabled.", broker.logging.audit)
}
