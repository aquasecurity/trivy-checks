# METADATA
# title: Enable Performance Insights to detect potential problems
# description: |
#   Enabling Performance insights allows for greater depth in monitoring data.
#   For example, information about active sessions could help diagose a compromise or assist in the investigation
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://aws.amazon.com/rds/performance-insights/
# custom:
#   id: AWS-0133
#   aliases:
#     - AVD-AWS-0133
#     - enable-performance-insights
#   long_id: aws-rds-enable-performance-insights
#   provider: aws
#   service: rds
#   severity: LOW
#   recommended_action: Enable performance insights
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rds
#             provider: aws
#   examples: checks/cloud/aws/rds/enable_performance_insights.yaml
package builtin.aws.rds.aws0133

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.aws.rds.clusters
	some instance in cluster.instances
	isManaged(instance)
	not instance.instance.performanceinsights.enabled.value
	res := result.new(
		"Instance does not have performance insights enabled.",
		metadata.obj_by_path(instance.instance, ["performanceinsights", "enabled"]),
	)
}

deny contains res if {
	some instance in input.aws.rds.instances
	isManaged(instance)
	not instance.performanceinsights.enabled.value
	res := result.new(
		"Instance does not have performance insights enabled.",
		metadata.obj_by_path(instance, ["performanceinsights", "enabled"]),
	)
}
