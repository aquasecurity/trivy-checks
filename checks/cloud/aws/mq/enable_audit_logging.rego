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
#   examples: checks/cloud/aws/mq/enable_audit_logging.yaml
package builtin.aws.mq.aws0070

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some broker in input.aws.mq.brokers
	logging_disabled(broker)
	res := result.new(
		"Broker does not have audit logging enabled.",
		metadata.obj_by_path(broker, ["logging", "audit"]),
	)
}

logging_disabled(broker) if value.is_false(broker.logging.audit)

logging_disabled(broker) if not broker.logging.audit
