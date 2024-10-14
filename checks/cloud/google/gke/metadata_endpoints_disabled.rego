# METADATA
# title: Legacy metadata endpoints enabled.
# description: |
#   The Compute Engine instance metadata server exposes legacy v0.1 and v1beta1 endpoints, which do not enforce metadata query headers.
#
#   This is a feature in the v1 APIs that makes it more difficult for a potential attacker to retrieve instance metadata.
#
#   Unless specifically required, we recommend you disable these legacy APIs.
#
#   When setting the <code>metadata</code> block, the default value for <code>disable-legacy-endpoints</code> is set to true, they should not be explicitly enabled.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#protect_node_metadata_default_for_112
# custom:
#   id: AVD-GCP-0048
#   avd_id: AVD-GCP-0048
#   provider: google
#   service: gke
#   severity: HIGH
#   short_code: metadata-endpoints-disabled
#   recommended_action: Disable legacy metadata endpoints
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#metadata
#     good_examples: checks/cloud/google/gke/metadata_endpoints_disabled.yaml
#     bad_examples: checks/cloud/google/gke/metadata_endpoints_disabled.yaml
package builtin.google.gke.google0048

import rego.v1

deny contains res if {
	some cluster in input.google.gke.clusters
	cluster.removedefaultnodepool.value == true
	some pool in cluster.nodepools
	pool.nodeconfig.enablelegacyendpoints.value == true
	res := result.new(
		"Cluster has legacy metadata endpoints enabled.",
		pool.nodeconfig.enablelegacyendpoints,
	)
}

deny contains res if {
	some cluster in input.google.gke.clusters
	not cluster.removedefaultnodepool.value
	cluster.nodeconfig.enablelegacyendpoints.value == true
	res := result.new(
		"Cluster has legacy metadata endpoints enabled.",
		cluster.nodeconfig.enablelegacyendpoints,
	)
}
