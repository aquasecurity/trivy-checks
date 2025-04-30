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
#   examples: checks/cloud/google/gke/enable_auto_upgrade.yaml
package builtin.google.gke.google0058

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	autopilot_disabled(cluster)
	some pool in cluster.nodepools
	autoupgrade_is_disabled_for_pool(pool)
	res := result.new(
		"Node pool does not have auto-repair enabled.",
		metadata.obj_by_path(pool, ["management", "enableautoupgrade"]),
	)
}

autoupgrade_is_disabled_for_pool(pool) if value.is_false(pool.management.enableautoupgrade)

autoupgrade_is_disabled_for_pool(pool) if not pool.management.enableautoupgrade

autopilot_disabled(cluster) if value.is_false(cluster.enableautpilot)

autopilot_disabled(cluster) if not cluster.enableautpilot

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	cluster.enableautpilot.value
	autoupgrade_is_disabled(cluster)
	res := result.new(
		"Node pool does not have auto-repair enabled.",
		metadata.obj_by_path(cluster, ["autoscaling", "autoprovisioningdefaults", "management", "enableautoupgrade"]),
	)
}

autoupgrade_is_disabled(cluster) if value.is_false(cluster.autoscaling.autoprovisioningdefaults.management.enableautoupgrade)

autoupgrade_is_disabled(cluster) if not cluster.autoscaling.autoprovisioningdefaults.management.enableautoupgrade
