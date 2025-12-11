# METADATA
# title: ECS clusters should have container insights enabled
# description: |
#   Cloudwatch Container Insights provide more metrics and logs for container based applications and micro services.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html
# custom:
#   id: AVD-AWS-0034
#   avd_id: AVD-AWS-0034
#   provider: aws
#   service: ecs
#   severity: LOW
#   short_code: enable-container-insight
#   recommended_action: Enable Container Insights
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ecs
#             provider: aws
#   examples: checks/cloud/aws/ecs/enable_container_insight.yaml
package builtin.aws.ecs.aws0034

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.aws.ecs.clusters
	not cluster.settings.containerinsightsenabled.value
	res := result.new(
		"Cluster does not have container insights enabled.",
		metadata.obj_by_path(cluster, ["settings", "containerinsightsenabled"]),
	)
}
