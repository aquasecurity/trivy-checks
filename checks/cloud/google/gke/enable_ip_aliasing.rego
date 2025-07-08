# METADATA
# title: Clusters should have IP aliasing enabled
# description: |
#   IP aliasing allows the reuse of public IPs internally, removing the need for a NAT gateway.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0049
#   aliases:
#     - AVD-GCP-0049
#     - enable-ip-aliasing
#   long_id: google-gke-enable-ip-aliasing
#   provider: google
#   service: gke
#   severity: LOW
#   recommended_action: Enable IP aliasing
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/enable_ip_aliasing.yaml
package builtin.google.gke.google0049

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	not cluster.ipallocationpolicy.enabled.value
	res := result.new(
		"Cluster has IP aliasing disabled.",
		metadata.obj_by_path(cluster, ["ipallocationpolicy", "enabled"]),
	)
}
