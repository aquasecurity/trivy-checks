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
#   examples: checks/cloud/google/gke/enable_auto_repair.yaml
package builtin.google.gke.google0063

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	autopilot_disabled(cluster)
	some pool in cluster.nodepools
	autorepair_is_disabled_for_pool(pool)
	res := result.new(
		"Node pool does not have auto-repair enabled.",
		metadata.obj_by_path(pool, ["management", "enableautorepair"]),
	)
}

autorepair_is_disabled_for_pool(pool) if value.is_false(pool.management.enableautorepair)

autorepair_is_disabled_for_pool(pool) if not pool.management.enableautorepair

autopilot_disabled(cluster) if value.is_false(cluster.enableautpilot)

autopilot_disabled(cluster) if not cluster.enableautpilot

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	cluster.enableautpilot.value
	autorepair_is_disabled(cluster)
	res := result.new(
		"Node pool does not have auto-repair enabled.",
		metadata.obj_by_path(cluster, ["autoscaling", "autoprovisioningdefaults", "management", "enableautorepair"]),
	)
}

autorepair_is_disabled(cluster) if value.is_false(cluster.autoscaling.autoprovisioningdefaults.management.enableautorepair)

autorepair_is_disabled(cluster) if not cluster.autoscaling.autoprovisioningdefaults.management.enableautorepair
