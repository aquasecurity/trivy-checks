# METADATA
# title: Neptune logs export should be enabled
# description: |
#   Neptune does not have auditing by default. To ensure that you are able to accurately audit the usage of your Neptune instance you should enable export logs.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html
# custom:
#   id: AVD-AWS-0075
#   avd_id: AVD-AWS-0075
#   provider: aws
#   service: neptune
#   severity: MEDIUM
#   short_code: enable-log-export
#   recommended_action: Enable export logs
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: neptune
#             provider: aws
#   examples: checks/cloud/aws/neptune/enable_log_export.yaml
package builtin.aws.neptune.aws0075

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.aws.neptune.clusters
	not cluster.logging.audit.value
	res := result.new(
		"Cluster does not have audit logging enabled.",
		metadata.obj_by_path(cluster, ["logging", "audit"]),
	)
}
