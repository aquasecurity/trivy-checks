# METADATA
# title: Ensure RBAC is enabled on AKS clusters
# description: |
#   Using Kubernetes role-based access control (RBAC), you can grant users, groups, and service accounts access to only the resources they need.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/aks/concepts-identity
# custom:
#   id: AZU-0042
#   aliases:
#     - AVD-AZU-0042
#     - use-rbac-permissions
#   long_id: azure-container-use-rbac-permissions
#   provider: azure
#   service: container
#   severity: HIGH
#   recommended_action: Enable RBAC
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: container
#             provider: azure
#   examples: checks/cloud/azure/container/use_rbac_permissions.yaml
package builtin.azure.container.azure0042

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.azure.container.kubernetesclusters
	isManaged(cluster)
	not cluster.rolebasedaccesscontrol.enabled.value
	res := result.new(
		"RBAC is not enabled on cluster",
		metadata.obj_by_path(cluster, ["rolebasedaccesscontrol", "enabled"]),
	)
}
