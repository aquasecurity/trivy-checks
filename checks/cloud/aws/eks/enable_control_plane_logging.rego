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
#   examples: checks/cloud/aws/eks/enable_control_plane_logging.yaml
package builtin.aws.eks.aws0038

import rego.v1

import data.lib.cloud.metadata

logging_types := {
	"api": "API",
	"audit": "audit",
	"authenticator": "authenticator",
	"controllermanager": "controller manager",
	"scheduler": "scheduler",
}

deny contains res if {
	some cluster in input.aws.eks.clusters
	some logging_type, display_name in logging_types
	not cluster.logging[logging_type].value
	res := result.new(
		sprintf("Control plane %s logging is not enabled.", [display_name]),
		metadata.obj_by_path(cluster, ["logging", logging_type]),
	)
}
