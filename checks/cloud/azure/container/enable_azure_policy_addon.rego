# METADATA
# title: Ensure AKS cluster has Azure Policy add-on enabled
# description: |
#   Azure Kubernetes Service should enable Azure Policy Add-On to enforce compliance and governance policies on the cluster. The add-on extends Gatekeeper v3, an admission controller webhook for Open Policy Agent (OPA).
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#azure_policy_enabled
# custom:
#   id: AZU-0066
#   long_id: azure-container-enable-azure-policy-addon
#   aliases:
#     - AVD-AZU-0066
#     - enable-azure-policy-addon
#   provider: azure
#   service: container
#   severity: LOW
#   recommended_action: Enable Azure Policy add-on on the AKS cluster to enforce governance policies.
#   minimum_trivy_version: 0.68.0
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: container
#             provider: azure
#   examples: checks/cloud/azure/container/enable_azure_policy_addon.yaml
package builtin.azure.container.azure0066

import rego.v1

import data.lib.cloud.metadata

import data.lib.cloud.value

deny contains res if {
	some cluster in input.azure.container.kubernetesclusters
	isManaged(cluster)
	is_policy_disabled(cluster)
	res := result.new(
		"Cluster does not have Azure Policy add-on enabled.",
		metadata.obj_by_path(cluster, ["addonprofile", "azurepolicy", "enabled"]),
	)
}

is_policy_disabled(cluster) if not cluster.addonprofile.azurepolicy.enabled
is_policy_disabled(cluster) if value.is_false(cluster.addonprofile.azurepolicy.enabled)
