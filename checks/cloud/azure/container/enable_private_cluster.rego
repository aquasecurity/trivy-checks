# METADATA
# title: Ensure AKS cluster has private cluster enabled
# description: |
#   A public AKS API server endpoint increases exposure to unauthorized access or attack. Enable private cluster to ensure the API server endpoint is only accessible from within the virtual network.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#private_cluster_enabled
# custom:
#   id: AZU-0065
#   long_id: azure-container-enable-private-cluster
#   aliases:
#     - AVD-AZU-0065
#     - enable-private-cluster
#   provider: azure
#   service: container
#   severity: MEDIUM
#   recommended_action: Provision the AKS cluster with `private_cluster_enabled = true` and use private endpoints.
#   minimum_trivy_version: 0.68.0
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: container
#             provider: azure
#   examples: checks/cloud/azure/container/enable_private_cluster.yaml
package builtin.azure.container.azure0065

import rego.v1

import data.lib.cloud.metadata

import data.lib.cloud.value

deny contains res if {
	some cluster in input.azure.container.kubernetesclusters
	isManaged(cluster)
	is_private_cluster_disabled(cluster)
	res := result.new(
		"Cluster does not have private cluster enabled.",
		metadata.obj_by_path(cluster, ["enableprivatecluster"]),
	)
}

is_private_cluster_disabled(cluster) if not cluster.enableprivatecluster
is_private_cluster_disabled(cluster) if value.is_false(cluster.enableprivatecluster)
