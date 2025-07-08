# METADATA
# title: Clusters should be configured with Labels
# description: |
#   Labels make it easier to manage assets and differentiate between clusters and environments, allowing the mapping of computational resources to the wider organisational structure.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0051
#   aliases:
#     - AVD-GCP-0051
#     - use-cluster-labels
#   long_id: google-gke-use-cluster-labels
#   provider: google
#   service: gke
#   severity: LOW
#   recommended_action: Set cluster resource labels
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/use_cluster_labels.yaml
package builtin.google.gke.google0051

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	count(cluster.resourcelabels.value) == 0
	res := result.new(
		"Cluster does not use GCE resource labels.",
		metadata.obj_by_path(cluster, ["resourcelabels"]),
	)
}
