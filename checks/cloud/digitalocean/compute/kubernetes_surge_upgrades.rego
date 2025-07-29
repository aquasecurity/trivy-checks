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
#   examples: checks/cloud/digitalocean/compute/kubernetes_surge_upgrades.yaml
package builtin.digitalocean.compute.digitalocean0005

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.digitalocean.compute.kubernetesclusters
	isManaged(cluster)
	superupgrade_disabled(cluster)
	res := result.new(
		"Surge upgrades are disabled in your Kubernetes cluster. Please enable this feature.",
		metadata.obj_by_path(cluster, ["surgeupgrade"]),
	)
}

superupgrade_disabled(cluster) if value.is_false(cluster.surgeupgrade)

superupgrade_disabled(cluster) if not cluster.surgeupgrade
