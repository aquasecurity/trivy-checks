# METADATA
# title: Node metadata value disables metadata concealment.
# description: |
#   If the <code>workload_metadata_config</code> block within <code>node_config</code> is included, the <code>node_metadata</code> attribute should be configured securely.
#
#   The attribute should be set to <code>SECURE</code> to use metadata concealment, or <code>GKE_METADATA_SERVER</code> if workload identity is enabled. This ensures that the VM metadata is not unnecessarily exposed to pods.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata#create-concealed
# custom:
#   id: AVD-GCP-0057
#   avd_id: AVD-GCP-0057
#   provider: google
#   service: gke
#   severity: HIGH
#   short_code: node-metadata-security
#   recommended_action: Set node metadata to SECURE or GKE_METADATA_SERVER
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#node_metadata
#     good_examples: checks/cloud/google/gke/node_metadata_security.tf.go
#     bad_examples: checks/cloud/google/gke/node_metadata_security.tf.go
package builtin.google.gke.google0057

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	metadata := cluster.nodeconfig.workloadmetadataconfig.nodemetadata
	is_exposes(metadata.value)
	res := result.new("Cluster exposes node metadata of pools by default.", metadata)
}

deny contains res if {
	some cluster in input.google.gke.clusters
	some pool in cluster.nodepools
	metadata := pool.nodeconfig.workloadmetadataconfig.nodemetadata
	is_exposes(metadata.value)
	res := result.new("Cluster exposes node metadata of pools by default.", metadata)
}

is_exposes(metadata) := metadata in {"UNSPECIFIED", "EXPOSE"}
