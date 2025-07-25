# METADATA
# title: Clusters should be set to private
# description: |
#   Enabling private nodes on a cluster ensures the nodes are only available internally as they will only be assigned internal addresses.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0059
#   aliases:
#     - AVD-GCP-0059
#     - enable-private-cluster
#   long_id: google-gke-enable-private-cluster
#   provider: google
#   service: gke
#   severity: MEDIUM
#   recommended_action: Enable private cluster
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/enable_private_cluster.yaml
package builtin.google.gke.google0059

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	not cluster.privatecluster.enableprivatenodes.value
	res := result.new(
		"Cluster does not have private nodes.",
		metadata.obj_by_path(cluster, ["privatecluster", "enableprivatenodes"]),
	)
}
