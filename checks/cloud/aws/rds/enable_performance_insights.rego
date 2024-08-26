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
#   id: AVD-AWS-0133
#   avd_id: AVD-AWS-0133
#   provider: aws
#   service: rds
#   severity: LOW
#   short_code: enable-performance-insights
#   recommended_action: Enable performance insights
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rds
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance#performance_insights_kms_key_id
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#performance_insights_kms_key_id
#     good_examples: checks/cloud/aws/rds/enable_performance_insights.tf.go
#     bad_examples: checks/cloud/aws/rds/enable_performance_insights.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/rds/enable_performance_insights.cf.go
#     bad_examples: checks/cloud/aws/rds/enable_performance_insights.cf.go
package builtin.aws.rds.aws0133

import rego.v1

deny contains res if {
	some cluster in input.aws.rds.clusters
	some instance in cluster.instances
	isManaged(instance)
	not instance.instance.performanceinsights.enabled.value
	res := result.new(
		"Instance does not have performance insights enabled.",
		object.get(instance.instance.performanceinsights, "enabled", instance.instance.performanceinsights),
	)
}

deny contains res if {
	some instance in input.aws.rds.instances
	isManaged(instance)
	not instance.performanceinsights.enabled.value
	res := result.new(
		"Instance does not have performance insights enabled.",
		object.get(instance.performanceinsights, "enabled", instance.performanceinsights),
	)
}
