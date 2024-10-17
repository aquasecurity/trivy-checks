# METADATA
# title: Clusters should be set to private
# description: |
#   Enabling private nodes on a cluster ensures the nodes are only available internally as they will only be assigned internal addresses.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0059
#   avd_id: AVD-GCP-0059
#   provider: google
#   service: gke
#   severity: MEDIUM
#   short_code: enable-private-cluster
#   recommended_action: Enable private cluster
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_private_nodes
#     good_examples: checks/cloud/google/gke/enable_private_cluster.yaml
#     bad_examples: checks/cloud/google/gke/enable_private_cluster.yaml
package builtin.google.gke.google0059

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	cluster.privatecluster.enableprivatenodes.value == false
	res := result.new(
		"Cluster does not have private nodes.",
		cluster.privatecluster.enableprivatenodes,
	)
}
