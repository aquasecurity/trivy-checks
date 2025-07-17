# METADATA
# title: Deployment not allowed
# description: |
#   This check ensures that Kubernetes Deployments are not used in your environment.
#   Deployments may be restricted for various reasons, such as the need to use other controllers (e.g., StatefulSets, DaemonSets) or the avoidance of certain deployment strategies.
#
#   Avoid using the 'Deployment' kind to ensure compliance with your organization's deployment strategy.
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/workloads/controllers/deployment/
# custom:
#   id: USR-KUBE-0001
#   avd_id: USR-KUBE-0001
#   severity: HIGH
#   short_code: no-deployment-allowed
#   recommended_action: Avoid using Kubernetes Deployments. Consider alternative resources like StatefulSets or DaemonSets.
#   input:
#     selector:
#       - type: kubernetes
package user.kubernetes.no_deployment_allowed

import rego.v1

deny contains res if {
	input.kind == "Deployment"
	res := result.new(
		sprintf("Found deployment '%s' but deployments are not allowed", [input.metadata.name]),
		input.metadata,
	)
}
