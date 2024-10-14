# METADATA
# title: Ensure AKS cluster has Network Policy configured
# description: |
#   The Kubernetes object type NetworkPolicy should be defined to have opportunity allow or block traffic to pods, as in a Kubernetes cluster configured with default settings, all pods can discover and communicate with each other without any restrictions.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/services-networking/network-policies
# custom:
#   id: AVD-AZU-0043
#   avd_id: AVD-AZU-0043
#   provider: azure
#   service: container
#   severity: HIGH
#   short_code: configured-network-policy
#   recommended_action: Configure a network policy
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: container
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#network_policy
#     good_examples: checks/cloud/azure/container/configured_network_policy.yaml
#     bad_examples: checks/cloud/azure/container/configured_network_policy.yaml
package builtin.azure.container.azure0043

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.azure.container.kubernetesclusters
	network_policy_missed(cluster)
	res := result.new(
		"Kubernetes cluster does not have a network policy set.",
		metadata.obj_by_path(cluster, ["networkprofile", "networkpolicy"]),
	)
}

network_policy_missed(cluster) if value.is_empty(cluster.networkprofile.networkpolicy)

network_policy_missed(cluster) if not cluster.networkprofile.networkpolicy
