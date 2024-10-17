# METADATA
# title: EKS Clusters should have cluster control plane logging turned on
# description: |
#   By default cluster control plane logging is not turned on. Logging is available for audit, api, authenticator, controllerManager and scheduler. All logging should be turned on for cluster control plane.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
# custom:
#   id: AVD-AWS-0038
#   avd_id: AVD-AWS-0038
#   provider: aws
#   service: eks
#   severity: MEDIUM
#   short_code: enable-control-plane-logging
#   recommended_action: Enable logging for the EKS control plane
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: eks
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#enabled_cluster_log_types
#     good_examples: checks/cloud/aws/eks/enable_control_plane_logging.yaml
#     bad_examples: checks/cloud/aws/eks/enable_control_plane_logging.yaml
package builtin.aws.eks.aws0038

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.aws.eks.clusters
	not cluster.logging.api.value
	res := result.new(
		"Control plane API logging is not enabled.",
		metadata.obj_by_path(cluster, ["logging", "api"]),
	)
}

deny contains res if {
	some cluster in input.aws.eks.clusters
	not cluster.logging.audit.value
	res := result.new(
		"Control plane audit logging is not enabled.",
		metadata.obj_by_path(cluster, ["logging", "audit"]),
	)
}

deny contains res if {
	some cluster in input.aws.eks.clusters
	not cluster.logging.authenticator.value
	res := result.new(
		"Control plane authenticator logging is not enabled.",
		metadata.obj_by_path(cluster, ["logging", "authenticator"]),
	)
}

deny contains res if {
	some cluster in input.aws.eks.clusters
	not cluster.logging.controllermanager.value
	res := result.new(
		"Control plane controller manager logging is not enabled.",
		metadata.obj_by_path(cluster, ["logging", "controllermanager"]),
	)
}

deny contains res if {
	some cluster in input.aws.eks.clusters
	not cluster.logging.scheduler.value
	res := result.new(
		"Control plane scheduler logging is not enabled.",
		metadata.obj_by_path(cluster, ["logging", "scheduler"]),
	)
}
