# METADATA
# title: The Kubernetes cluster does not enable surge upgrades
# description: |
#   While upgrading your cluster, workloads will temporarily be moved to new nodes. A small cost will follow, but as a bonus, you won't experience downtime.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.digitalocean.com/products/kubernetes/how-to/upgrade-cluster/#surge-upgrades
# custom:
#   id: AVD-DIG-0005
#   avd_id: AVD-DIG-0005
#   provider: digitalocean
#   service: compute
#   severity: MEDIUM
#   short_code: surge-upgrades-not-enabled
#   recommended_action: Enable surge upgrades in your Kubernetes cluster
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: digitalocean
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/kubernetes_cluster#surge_upgrade
#     good_examples: checks/cloud/digitalocean/compute/kubernetes_surge_upgrades.tf.go
#     bad_examples: checks/cloud/digitalocean/compute/kubernetes_surge_upgrades.tf.go
package builtin.digitalocean.compute.digitalocean0005

import rego.v1

deny contains res if {
	some cluster in input.digitalocean.compute.kubernetesclusters
	isManaged(cluster)
	not cluster.surgeupgrade.value
	res := result.new(
		"Surge upgrades are disabled in your Kubernetes cluster. Please enable this feature.",
		object.get(cluster, "surgeupgrade", cluster),
	)
}
