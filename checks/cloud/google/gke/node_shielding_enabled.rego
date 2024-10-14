# METADATA
# title: Shielded GKE nodes not enabled.
# description: |
#   CIS GKE Benchmark Recommendation: 6.5.5. Ensure Shielded GKE Nodes are Enabled
#
#   Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes
# custom:
#   id: AVD-GCP-0055
#   avd_id: AVD-GCP-0055
#   provider: google
#   service: gke
#   severity: HIGH
#   short_code: node-shielding-enabled
#   recommended_action: Enable node shielding
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_shielded_nodes
#     good_examples: checks/cloud/google/gke/node_shielding_enabled.yaml
#     bad_examples: checks/cloud/google/gke/node_shielding_enabled.yaml
package builtin.google.gke.google0055

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	cluster.enableshieldednodes.value == false
	res := result.new("Cluster has shielded nodes disabled.", cluster.enableshieldednodes)
}
