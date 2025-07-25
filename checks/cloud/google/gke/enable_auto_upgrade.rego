# METADATA
# title: Kubernetes should have 'Automatic upgrade' enabled
# description: |
#   Automatic updates keep nodes updated with the latest cluster master version.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0058
#   aliases:
#     - AVD-GCP-0058
#     - enable-auto-upgrade
#   long_id: google-gke-enable-auto-upgrade
#   provider: google
#   service: gke
#   severity: LOW
#   recommended_action: Enable automatic upgrades
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/enable_auto_upgrade.yaml
package builtin.google.gke.google0058

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	some pool in cluster.nodepools
	not pool.management.enableautoupgrade.value
	res := result.new(
		"Node pool does not have auto-upgraade enabled.",
		metadata.obj_by_path(pool, ["management", "enableautoupgrade"]),
	)
}
