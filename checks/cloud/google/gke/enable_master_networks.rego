# METADATA
# title: Master authorized networks should be configured on GKE clusters
# description: |
#   Enabling authorized networks means you can restrict master access to a fixed set of CIDR ranges
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0061
#   avd_id: AVD-GCP-0061
#   provider: google
#   service: gke
#   severity: HIGH
#   short_code: enable-master-networks
#   recommended_action: Enable master authorized networks
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#
#     good_examples: checks/cloud/google/gke/enable_master_networks.yaml
#     bad_examples: checks/cloud/google/gke/enable_master_networks.yaml
package builtin.google.gke.google0061

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	cluster.masterauthorizednetworks.enabled.value == false
	res := result.new(
		"Cluster does not have master authorized networks enabled.",
		cluster.masterauthorizednetworks.enabled,
	)
}
