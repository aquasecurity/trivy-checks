# METADATA
# title: Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image
# description: |
#   GKE supports several OS image types but COS is the recommended OS image to use on cluster nodes for enhanced security
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0054
#   avd_id: AVD-GCP-0054
#   provider: google
#   service: gke
#   severity: LOW
#   short_code: node-pool-uses-cos
#   recommended_action: Use the COS image type
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/node_pool_uses_cos.yaml
package builtin.google.gke.google0054

import data.lib.cloud.value
import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	autopilot_disabled(cluster)
	image_type := cluster.nodeconfig.imagetype
	image_type_is_not_cos(image_type, {"cos", "cos_containerd", ""})
	res := result.new(
		"Cluster is not configuring node pools to use the COS containerd image type by default.",
		image_type,
	)
}

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	autopilot_disabled(cluster)
	some pool in cluster.nodepools
	image_type := pool.nodeconfig.imagetype
	image_type_is_not_cos(image_type, {"cos", "cos_containerd"})
	res := result.new(
		"Node pool is not using the COS containerd image type.",
		image_type,
	)
}

autopilot_disabled(cluster) if value.is_false(cluster.enableautpilot)

autopilot_disabled(cluster) if not cluster.enableautpilot

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	cluster.enableautpilot.value
	image_type := cluster.autoscaling.autoprovisioningdefaults.imagetype
	image_type_is_not_cos(image_type, {"cos", "cos_containerd"})
	res := result.new(
		"Node pool is not using the COS containerd image type.",
		image_type,
	)
}

image_type_is_not_cos(image_type, _) if value.is_empty(image_type)

image_type_is_not_cos(image_type, allowed) if {
	value.is_not_empty(image_type)
	not lower(image_type.value) in allowed
}
