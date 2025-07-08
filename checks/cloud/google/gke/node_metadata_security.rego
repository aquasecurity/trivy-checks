# METADATA
# title: Node metadata value disables metadata concealment.
# description: |
#   In provider versions prior to 4:
#   The attribute <code>workload_metadata_config.node_metadata</code> configures how node metadata is exposed to workloads. It should be set to <code>SECURE</code> to limit metadata exposure, or <code>GKE_METADATA_SERVER</code> if Workload Identity is enabled.
#
#   Starting with provider version 4:
#   The attribute <code>node_metadata</code> has been removed. Instead, <code>workload_metadata_configuration.mode</code> controls node metadata exposure. When Workload Identity is enabled, it should be set to <code>GKE_METADATA</code> to prevent unnecessary exposure of the metadata API to workloads.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata#create-concealed
# custom:
#   id: GCP-0057
#   aliases:
#     - AVD-GCP-0057
#     - node-metadata-security
#   long_id: google-gke-node-metadata-security
#   provider: google
#   service: gke
#   severity: HIGH
#   recommended_action: Set mode to GKE_METADATA
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/node_metadata_security.yaml
package builtin.google.gke.google0057

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	metadata := cluster.nodeconfig.workloadmetadataconfig.nodemetadata
	is_exposes(metadata.value)
	res := result.new("Cluster exposes node metadata of pools by default.", metadata)
}

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	some pool in cluster.nodepools
	metadata := pool.nodeconfig.workloadmetadataconfig.nodemetadata
	is_exposes(metadata.value)
	res := result.new("Cluster exposes node metadata of pools by default.", metadata)
}

is_exposes(metadata) := metadata in {
	"UNSPECIFIED", "EXPOSE", # https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1beta1/NodeConfig#nodemetadata
	"MODE_UNSPECIFIED", "GCE_METADATA", # https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1beta1/NodeConfig#mode
}
