# METADATA
# title: Kubernetes should have 'Automatic upgrade' enabled
# description: |
#   Automatic updates keep nodes updated with the latest cluster master version.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0058
#   avd_id: AVD-GCP-0058
#   provider: google
#   service: gke
#   severity: LOW
#   short_code: enable-auto-upgrade
#   recommended_action: Enable automatic upgrades
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_node_pool#auto_upgrade
#     good_examples: checks/cloud/google/gke/enable_auto_upgrade.yaml
#     bad_examples: checks/cloud/google/gke/enable_auto_upgrade.yaml
package builtin.google.gke.google0058

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	some pool in cluster.nodepools
	pool.management.enableautoupgrade.value == false
	res := result.new("Node pool does not have auto-upgraade enabled.", pool.management.enableautoupgrade)
}
