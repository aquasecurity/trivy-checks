# METADATA
# title: Ensure AKS has an API Server Authorized IP Ranges enabled
# description: |
#   The API server is the central way to interact with and manage a cluster. To improve cluster security and minimize attacks, the API server should only be accessible from a limited set of IP address ranges.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges
# custom:
#   id: AVD-AZU-0041
#   avd_id: AVD-AZU-0041
#   provider: azure
#   service: container
#   severity: CRITICAL
#   short_code: limit-authorized-ips
#   recommended_action: Limit the access to the API server to a limited IP range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: container
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#authorized_ip_ranges
#     good_examples: checks/cloud/azure/container/limit_authorized_ips.tf.go
#     bad_examples: checks/cloud/azure/container/limit_authorized_ips.tf.go
package builtin.azure.container.azure0041

import rego.v1

deny contains res if {
	some cluster in input.azure.container.kubernetesclusters
	isManaged(cluster)
	not is_private_cluster(cluster)
	not is_limit_ip_ranges(cluster)
	res := result.new(
		"Cluster does not limit API access to specific IP addresses.",
		object.get(cluster, "apiserverauthorizedipranges", cluster),
	)
}

is_limit_ip_ranges(cluster) := count(cluster.apiserverauthorizedipranges) > 0

is_private_cluster(cluster) := cluster.enableprivatecluster.value
