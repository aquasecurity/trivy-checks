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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_node_pool#image_type
#     good_examples: checks/cloud/google/gke/node_pool_uses_cos.tf.go
#     bad_examples: checks/cloud/google/gke/node_pool_uses_cos.tf.go
package builtin.google.gke.google0054

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	image_type := cluster.nodeconfig.imagetype
	not lower(image_type.value) in {"cos", "cos_containerd", ""}
	res := result.new(
		"Cluster is not configuring node pools to use the COS containerd image type by default.",
		image_type,
	)
}

deny contains res if {
	some cluster in input.google.gke.clusters
	some pool in cluster.nodepools
	image_type := pool.nodeconfig.imagetype
	not lower(image_type.value) in {"cos", "cos_containerd"}
	res := result.new(
		"Node pool is not using the COS containerd image type.",
		image_type,
	)
}
