# METADATA
# title: MQ Broker should have general logging enabled
# description: |
#   Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html
# custom:
#   id: AVD-AWS-0071
#   avd_id: AVD-AWS-0071
#   provider: aws
#   service: mq
#   severity: LOW
#   short_code: enable-general-logging
#   recommended_action: Enable general logging
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: mq
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker#general
#     good_examples: checks/cloud/aws/mq/enable_general_logging.yaml
#     bad_examples: checks/cloud/aws/mq/enable_general_logging.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/mq/enable_general_logging.yaml
#     bad_examples: checks/cloud/aws/mq/enable_general_logging.yaml
package builtin.aws.mq.aws0071

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some broker in input.aws.mq.brokers
	logging_disabled(broker)
	res := result.new(
		"Broker does not have general logging enabled.",
		metadata.obj_by_path(broker, ["logging", "general"]),
	)
}

logging_disabled(broker) if value.is_false(broker.logging.general)

logging_disabled(broker) if not broker.logging.general
