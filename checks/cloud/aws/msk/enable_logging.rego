# METADATA
# title: Ensure MSK Cluster logging is enabled
# description: |
#   Managed streaming for Kafka can log to Cloud Watch, Kinesis Firehose and S3, at least one of these locations should be logged to
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/msk/latest/developerguide/msk-logging.html
# custom:
#   id: AVD-AWS-0074
#   avd_id: AVD-AWS-0074
#   provider: aws
#   service: msk
#   severity: MEDIUM
#   short_code: enable-logging
#   recommended_action: Enable logging
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: msk
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#
#     good_examples: checks/cloud/aws/msk/enable_logging.yaml
#     bad_examples: checks/cloud/aws/msk/enable_logging.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/msk/enable_logging.yaml
#     bad_examples: checks/cloud/aws/msk/enable_logging.yaml
package builtin.aws.msk.aws0074

import rego.v1

deny contains res if {
	some cluster in input.aws.msk.clusters
	not is_logging_enabled(cluster.logging.broker)
	res := result.new(
		"Cluster does not ship logs to any service.",
		cluster.logging.broker,
	)
}

is_logging_enabled(broker) if broker.s3.enabled.value

is_logging_enabled(broker) if broker.firehose.enabled.value

is_logging_enabled(broker) if broker.cloudwatch.enabled.value
