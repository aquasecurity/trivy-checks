# METADATA
# title: Master authorized networks should be configured on GKE clusters
# description: |
#   Enabling authorized networks means you can restrict master access to a fixed set of CIDR ranges
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0061
#   aliases:
#     - AVD-GCP-0061
#     - enable-master-networks
#   long_id: google-gke-enable-master-networks
#   provider: google
#   service: gke
#   severity: HIGH
#   recommended_action: Enable master authorized networks
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/enable_master_networks.yaml
package builtin.google.gke.google0061

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	not cluster.masterauthorizednetworks.enabled.value
	res := result.new(
		"Cluster does not have master authorized networks enabled.",
		metadata.obj_by_path(cluster, ["masterauthorizednetworks", "enabled"]),
	)
}
