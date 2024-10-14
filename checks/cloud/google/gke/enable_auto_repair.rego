# METADATA
# title: Kubernetes should have 'Automatic repair' enabled
# description: |
#   Automatic repair will monitor nodes and attempt repair when a node fails multiple subsequent health checks
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0063
#   avd_id: AVD-GCP-0063
#   provider: google
#   service: gke
#   severity: LOW
#   short_code: enable-auto-repair
#   recommended_action: Enable automatic repair
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_node_pool#auto_repair
#     good_examples: checks/cloud/google/gke/enable_auto_repair.yaml
#     bad_examples: checks/cloud/google/gke/enable_auto_repair.yaml
package builtin.google.gke.google0063

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	some pool in cluster.nodepools
	pool.management.enableautorepair.value == false
	res := result.new("Node pool does not have auto-repair enabled.", pool.management.enableautorepair)
}
