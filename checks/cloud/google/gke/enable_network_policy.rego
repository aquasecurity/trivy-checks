# METADATA
# title: Network Policy should be enabled on GKE clusters
# description: |
#   Enabling a network policy allows the segregation of network traffic by namespace
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0056
#   avd_id: AVD-GCP-0056
#   provider: google
#   service: gke
#   severity: MEDIUM
#   short_code: enable-network-policy
#   recommended_action: Enable network policy
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/enable_network_policy.yaml
package builtin.google.gke.google0056

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	not networkpolicy_enabled(cluster)
	not autopilot_enabled(cluster)
	not dataplane_v2_enabled(cluster)
	res := result.new(
		"Cluster does not have a network policy enabled.",
		metadata.obj_by_path(cluster, ["networkpolicy", "enabled"]),
	)
}

networkpolicy_enabled(cluster) if cluster.networkpolicy.enabled.value

autopilot_enabled(cluster) if cluster.enableautpilot.value

dataplane_v2_enabled(cluster) if cluster.datapathprovider.value == "ADVANCED_DATAPATH"
