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
#     good_examples: checks/cloud/azure/container/configured_network_policy.tf.go
#     bad_examples: checks/cloud/azure/container/configured_network_policy.tf.go
package builtin.azure.container.azure0043

import rego.v1

deny contains res if {
	some cluster in input.azure.container.kubernetesclusters
	not has_network_policy(cluster)
	res := result.new(
		"Kubernetes cluster does not have a network policy set.",
		object.get(cluster, ["networkprofile", "networkpolicy"], cluster),
	)
}

has_network_policy(cluster) := cluster.networkprofile.networkpolicy.value != ""
